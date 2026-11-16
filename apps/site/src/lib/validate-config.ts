/**
 * Validates generated advisorydeck.yml in the browser: the text is parsed back with a YAML parser
 * and checked against schemas/v1/image-config.schema.json plus the rules the image enforces that
 * a schema cannot express. Nothing is sent anywhere.
 */
import { Ajv2020, type ErrorObject } from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { parse } from 'yaml';
import type { ImageConfig } from '@advisorydeck/contract';
import { imageConfigProblems } from '@advisorydeck/contract/image-config';
import defsSchema from '@schemas/defs.schema.json';
import configSchema from '@schemas/image-config.schema.json';

let validator: ReturnType<Ajv2020['compile']> | undefined;

function compile(): ReturnType<Ajv2020['compile']> {
  if (validator === undefined) {
    const ajv = new Ajv2020({
      allErrors: true,
      strict: true,
      strictTypes: false,
      strictRequired: false,
    });
    addFormats(ajv);
    ajv.addSchema(defsSchema);
    validator = ajv.compile(configSchema);
  }
  return validator;
}

function describe(error: ErrorObject): string {
  const where = error.instancePath === '' ? '(root)' : error.instancePath;
  return `${where} ${error.message ?? 'is invalid'}`;
}

/** Problems with the YAML text; an empty list means the image will accept it. */
export function validateConfigYaml(text: string): string[] {
  let data: unknown;
  try {
    data = parse(text);
  } catch (error) {
    return [`YAML: ${String(error)}`];
  }
  const validate = compile();
  if (!validate(data)) {
    return (validate.errors ?? []).map(describe);
  }
  return imageConfigProblems(data as ImageConfig);
}
