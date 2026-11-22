// Release acceptance only: owned Node children, a fresh home and a loopback API.
// Uses the same child_process stdio modes as Desktop, without launching its UI.
const {spawn} = require('node:child_process');
const {createHash} = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const readline = require('node:readline');

async function main() {
  const [engine, directory, mode] = process.argv.slice(2);
  if (!['policy-read', 'policy-sign-out', 'stdio', 'version', 'help'].includes(mode)) throw Error('Unknown probe');
  // Refuse to replace any existing home, including one from an earlier probe.
  fs.mkdirSync(directory);
  const record = {name: mode, passed: false, timed_out: false, requests: 0, node_version: process.version};
  const server = http.createServer((request, response) => {
    record.requests++;
    request.resume();
    request.on('end', () => {
      response.writeHead(200, {'Content-Type': 'text/event-stream'});
      const item = {id: 'msg_startup_probe', type: 'message', role: 'assistant', status: 'completed',
        content: [{type: 'output_text', text: 'OK', annotations: []}]};
      for (const event of [
        {type: 'response.created', response: {id: 'startup-probe', status: 'in_progress', output: []}},
        {type: 'response.output_item.done', output_index: 0, item},
        {type: 'response.completed', response: {id: 'startup-probe', status: 'completed', output: [item],
          usage: {input_tokens: 1, output_tokens: 1, total_tokens: 2}}},
      ]) response.write(`data: ${JSON.stringify(event)}\n\n`);
      response.end();
    });
  });
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject); server.listen(0, '127.0.0.1', resolve);
    });
    await run(engine, directory, mode, `http://127.0.0.1:${server.address().port}/v1`, record);
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
  console.log(JSON.stringify(record));
  process.exitCode = record.passed ? 0 : 1;
}

async function run(engine, directory, mode, baseUrl, record) {
  const config = 'model="retry-probe-model"\nmodel_provider="probe"\ncli_auth_credentials_store="file"\n' +
    '[analytics]\nenabled=false\n[features]\nplugins=false\nresponses_websockets=false\nresponses_websockets_v2=false\n' +
    '[model_providers.probe]\nname="isolated desktop startup"\n' +
    `base_url="${baseUrl}"\nenv_key="CODEX_TIMEOUT_PROBE_KEY"\nwire_api="responses"\n` +
    'request_max_retries=0\nstream_max_retries=0\nsupports_websockets=false\n';
  fs.writeFileSync(path.join(directory, 'config.toml'), config);
  fs.writeFileSync(path.join(directory, 'auth.json'), JSON.stringify({OPENAI_API_KEY: 'fake-startup-key'}));
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
    !/^(CODEX_|OPENAI_|AZURE_OPENAI_|ELECTRON_|NODE_OPTIONS$)/i.test(key)));
  Object.assign(env, {CODEX_HOME: directory, CODEX_TIMEOUT_PROBE_KEY: 'fake-loopback-key',
    NO_PROXY: '127.0.0.1,localhost', RUST_LOG: 'warn', LOG_FORMAT: 'json'});
  const clientInfo = {name: 'codex_desktop', title: 'Codex Desktop', version: '0.0.0'};
  const args = mode === 'version' ? ['--version'] : mode === 'help' ? ['app-server', '--help'] :
    ['app-server', '--analytics-default-enabled'];
  if (mode.startsWith('policy-')) {
    args.push('--print-startup-config', '--startup-client-info', JSON.stringify(clientInfo));
    if (mode === 'policy-sign-out') args.push('--startup-sign-out');
  }
  const started = performance.now();
  const child = spawn(engine, args, {env, cwd: directory, windowsHide: true,
    stdio: [mode === 'stdio' ? 'pipe' : 'ignore', 'pipe', 'pipe']});
  let sequence = 0, stdout = '', phase = 'spawn';
  const pending = new Map(), notifications = [], observers = [];
  child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
  record.stderr = '';
  child.stderr.on('data', data => {record.stderr = (record.stderr + data).slice(-65536);});
  child.on('error', () => {record.failure = 'spawn';});
  child.stdin?.on('error', () => {record.failure = 'stdin';});
  const closed = new Promise(resolve => child.once('close', (code, signal) => {
    record.exit_code = code; record.signal = signal;
    for (const callback of [...pending.values(), ...observers]) callback.reject(Error('Probe child closed'));
    resolve();
  }));
  const timer = setTimeout(() => {record.timed_out = true; child.kill();}, 30000);
  let reader;
  if (mode === 'stdio') {
    reader = readline.createInterface({input: child.stdout});
    reader.on('line', line => {
      let value;
      try {value = JSON.parse(line);} catch {record.failure = 'jsonl'; child.kill(); return;}
      const callback = pending.get(value.id);
      if (callback) {
        pending.delete(value.id);
        value.error ? callback.reject(Error('RPC rejected')) : callback.resolve(value.result);
      } else {
        notifications.push(value);
        for (let i = observers.length - 1; i >= 0; i--) {
          if (observers[i].match(value)) observers.splice(i, 1)[0].resolve(value);
        }
      }
    });
  } else child.stdout.on('data', data => {
    stdout += data;
    if (stdout.length > 4194304) {record.failure = 'output-size'; child.kill();}
  });
  function send(value) {child.stdin.write(JSON.stringify(value) + '\n');}
  function call(method, params) {
    return new Promise((resolve, reject) => {
      const id = ++sequence;
      pending.set(id, {resolve, reject}); send({id, method, params});
    });
  }
  function waitNotification(match) {
    const existing = notifications.find(match);
    return existing ? Promise.resolve(existing) : new Promise((resolve, reject) => observers.push({match, resolve, reject}));
  }
  try {
    if (mode === 'stdio') {
      phase = 'initialize';
      await call('initialize', {clientInfo, capabilities: {experimentalApi: true}});
      record.initialized = true; send({method: 'initialized'});
      phase = 'configRequirements/read';
      record.policy = await call('configRequirements/read');
      phase = 'config/read';
      const configReply = await call('config/read', {cwd: directory, includeLayers: false});
      record.public_config_unchanged = configReply.config?.model_providers?.probe?.base_url === baseUrl;
      phase = 'thread/start';
      const reply = await call('thread/start', {cwd: directory, model: 'retry-probe-model', modelProvider: 'probe',
        approvalPolicy: 'never', sandbox: 'read-only', ephemeral: true});
      const threadId = reply.thread?.id;
      record.thread_started = typeof threadId === 'string';
      phase = 'turn/start';
      await call('turn/start', {threadId, input: [{type: 'text', text: '启动协议验收：Reply OK.'}]});
      const completed = await waitNotification(value => value.method === 'turn/completed' && value.params?.threadId === threadId);
      record.turn_completed = completed.params.turn.status === 'completed';
      child.stdin.end();
    }
    await closed;
    if (mode.startsWith('policy-')) {
      phase = 'startup-json';
      const value = JSON.parse(stdout);
      record.app_server_version = value.appServerVersion;
      record.policy = value.configRequirements;
    } else if (mode !== 'stdio') {
      record.stdout_bytes = Buffer.byteLength(stdout, 'utf8');
      record.stdout_sha256 = createHash('sha256').update(stdout).digest('hex');
    }
    record.config_unchanged = fs.readFileSync(path.join(directory, 'config.toml'), 'utf8') === config;
    record.auth_present = fs.existsSync(path.join(directory, 'auth.json'));
    const policyValid = record.policy != null && Object.hasOwn(record.policy, 'requirements');
    const responseValid = mode === 'stdio' ? policyValid && record.initialized && record.public_config_unchanged &&
      record.thread_started && record.turn_completed && record.requests === 1 : mode.startsWith('policy-') ?
      policyValid && typeof record.app_server_version === 'string' && record.requests === 0 :
      record.stdout_bytes > 0 && record.requests === 0;
    record.passed = !record.failure && !record.timed_out && record.exit_code === 0 && record.config_unchanged && responseValid;
  } catch {
    record.failure ??= phase;
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill();
    await closed;
    clearTimeout(timer); reader?.close();
  }
  record.elapsed_ms = Math.round(performance.now() - started);
}

main().catch(() => {console.log(JSON.stringify({passed: false, failure: 'probe-setup'})); process.exitCode = 1;});
