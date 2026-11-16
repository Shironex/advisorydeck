package notify

import (
	"context"
	"sync"
)

// Job is one message for one target, with callbacks to record the result.
type Job struct {
	Message Message
	// OnSent runs after the webhook accepted the message.
	OnSent func()
}

// Queue is the ordered work for one target.
type Queue struct {
	Target Target
	Jobs   []Job
	// OnDisabled runs once when the target answers 401/403/404/410; the rest of the
	// queue is dropped.
	OnDisabled func(status int)
}

// Dispatch drains every queue: messages to one webhook go out one at a time, in order,
// while different webhooks proceed in parallel. It returns when all queues are done.
func (s *Sender) Dispatch(ctx context.Context, queues []Queue) {
	s.defaults()
	var wg sync.WaitGroup
	for _, q := range queues {
		if len(q.Jobs) == 0 {
			continue
		}
		wg.Add(1)
		go func(q Queue) {
			defer wg.Done()
			s.drain(ctx, q)
		}(q)
	}
	wg.Wait()
}

func (s *Sender) drain(ctx context.Context, q Queue) {
	for i, job := range q.Jobs {
		outcome, status, err := s.Post(ctx, q.Target, job.Message.Payload)
		attrs := append(q.Target.LogAttrs(), "items", len(job.Message.Items), "outcome", outcome.String())
		switch outcome {
		case Sent:
			s.Log.Info("notification sent", attrs...)
			if job.OnSent != nil {
				job.OnSent()
			}
		case Dropped:
			s.Log.Error("notification dropped by the webhook", append(attrs, "status", status, "err", err)...)
		case Disabled:
			s.Log.Error("webhook disabled: it answered "+statusHint(status)+"; set a working URL in "+q.Target.URLEnv+" and restart",
				append(attrs, "status", status, "dropped_messages", len(q.Jobs)-i)...)
			if q.OnDisabled != nil {
				q.OnDisabled(status)
			}
			return
		case Failed:
			s.Log.Warn("notification not delivered, will retry next cycle", append(attrs, "status", status, "err", err)...)
			return // keep order: later messages wait for the next cycle too
		}
		if ctx.Err() != nil {
			return
		}
	}
}

func statusHint(status int) string {
	switch status {
	case 401:
		return "401 (invalid webhook token)"
	case 403:
		return "403 (no permission)"
	case 404:
		return "404 (webhook deleted or URL wrong)"
	case 410:
		return "410 (webhook gone)"
	}
	return "an error"
}
