// Validate an OSCAL document against a pinned NIST schema, with ajv.
//
// Python's `jsonschema` is not usable here: OSCAL's TokenDatatype pattern is
// `^(\p{L}|_)(\p{L}|\p{N}|[.\-_])*$`, and Python's `re` cannot compile a Unicode property escape, so
// `jsonschema` SKIPS the pattern it cannot read and reports a document valid that is not. ajv compiles it.
//
//   npm install --no-save ajv@8.17.1 ajv-formats@3.0.1
//   node scripts/oscal_validate.mjs tests/fixtures/oscal/oscal_assessment-results_schema.json out.json
//
// Exits 0 and prints VALID, or exits 1 and prints up to 25 errors with their instance paths.
import Ajv from "ajv";
import addFormats from "ajv-formats";
import { readFileSync } from "node:fs";

const [schemaPath, docPath] = process.argv.slice(2);
if (!schemaPath || !docPath) {
  console.error("usage: node scripts/oscal_validate.mjs <schema.json> <document.json>");
  process.exit(2);
}
const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
// NIST ships a $schema of draft 2020-12 while using `definitions`; ajv is told the dialect by its own
// configuration, and leaving the key in makes it try to fetch the meta-schema over the network.
delete schema.$schema;
const ajv = new Ajv({ strict: false, allErrors: true, allowUnionTypes: true });
addFormats(ajv);
const validate = ajv.compile(schema);
if (validate(JSON.parse(readFileSync(docPath, "utf8")))) {
  console.log("VALID");
  process.exit(0);
}
console.log(`INVALID: ${validate.errors.length} error(s)`);
for (const e of validate.errors.slice(0, 25)) {
  console.log(" ", e.instancePath || "/", e.message, JSON.stringify(e.params));
}
process.exit(1);
