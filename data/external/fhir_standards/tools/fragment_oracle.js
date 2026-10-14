const fs = require('fs');
const fhirpath = require('./node_modules/fhirpath');
const model = require('./node_modules/fhirpath/fhir-context/r4');
const jobs = JSON.parse(fs.readFileSync(0, 'utf8'));
const compiled = new Map();
const output = jobs.map(job => {
  const results = {}, errors = {};
  for (const rule of job.constraints) {
    let expression = rule.expression;
    if (rule.path === 'Observation.value[x]') expression = 'value.all(' + expression + ')';
    else if (rule.path === 'Observation.referenceRange') expression = 'referenceRange.all(' + expression + ')';
    else if (rule.path !== 'Observation') throw Error('Unsupported constraint context ' + rule.path);
    try {
      if (!compiled.has(expression)) compiled.set(expression, fhirpath.compile(expression, model));
      const value = compiled.get(expression)(job.resource, {resource: job.resource});
      if (value.length !== 1 || typeof value[0] !== 'boolean') throw Error('Non-Boolean result: '+JSON.stringify(value));
      results[rule.key] = value[0];
    } catch (error) { errors[rule.key] = String(error); }
  }
  return {id: job.id, results, errors};
});
process.stdout.write(JSON.stringify(output));
