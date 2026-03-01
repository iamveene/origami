// Origami GraphQL Attack Surface Mapper
// Detects GraphQL endpoints, introspects schemas, and identifies security issues

class GraphQLMapper {
  constructor() {
    this.endpoints = [];
    this.technologies = [];
    this.issues = [];
    this.schema = null;
    this.schemaTree = [];
  }

  detect() {
    this.endpoints = [];
    this.technologies = [];

    this._detectFromPerformanceEntries();
    this._detectApolloClient();
    this._detectUrql();
    this._detectRelay();
    this._detectFromScriptTags();
    this._detectFromMetaAndDataAttrs();

    // Deduplicate endpoints
    const seen = new Set();
    this.endpoints = this.endpoints.filter(ep => {
      if (seen.has(ep.url)) return false;
      seen.add(ep.url);
      return true;
    });

    return { endpoints: this.endpoints, technologies: this.technologies };
  }

  _detectFromPerformanceEntries() {
    try {
      const entries = performance.getEntriesByType('resource');
      const graphqlPatterns = [/\/graphql/i, /\/gql/i];

      for (const entry of entries) {
        const isGraphQL = graphqlPatterns.some(p => p.test(entry.name));
        if (isGraphQL) {
          this.endpoints.push({
            url: entry.name,
            source: 'performance-entry',
            initiatorType: entry.initiatorType || 'unknown'
          });
        }
      }
    } catch (e) {
      console.error('Origami: GraphQL performance entry detection error:', e.message);
    }
  }

  _detectApolloClient() {
    try {
      if (typeof window.__APOLLO_CLIENT__ !== 'undefined' && window.__APOLLO_CLIENT__) {
        this.technologies.push({ name: 'Apollo Client', detected: true, source: '__APOLLO_CLIENT__' });

        // Try to extract the endpoint from Apollo's link chain
        try {
          const client = window.__APOLLO_CLIENT__;
          if (client.link && client.link.options && client.link.options.uri) {
            const uri = client.link.options.uri;
            const resolved = new URL(uri, window.location.href).href;
            this.endpoints.push({ url: resolved, source: 'apollo-client-link' });
          }
        } catch (e) { /* link extraction failed */ }
      }

      if (typeof window.__APOLLO_DEVTOOLS_GLOBAL_HOOK__ !== 'undefined' && window.__APOLLO_DEVTOOLS_GLOBAL_HOOK__) {
        if (!this.technologies.some(t => t.name === 'Apollo Client')) {
          this.technologies.push({ name: 'Apollo Client (DevTools)', detected: true, source: '__APOLLO_DEVTOOLS_GLOBAL_HOOK__' });
        }
      }
    } catch (e) {
      console.error('Origami: Apollo detection error:', e.message);
    }
  }

  _detectUrql() {
    try {
      if (typeof window.__URQL__ !== 'undefined' && window.__URQL__) {
        this.technologies.push({ name: 'urql', detected: true, source: '__URQL__' });
      }
    } catch (e) {
      console.error('Origami: urql detection error:', e.message);
    }
  }

  _detectRelay() {
    try {
      if (typeof window.__RELAY_STORE__ !== 'undefined' && window.__RELAY_STORE__) {
        this.technologies.push({ name: 'Relay', detected: true, source: '__RELAY_STORE__' });
      }
    } catch (e) {
      console.error('Origami: Relay detection error:', e.message);
    }
  }

  _detectFromScriptTags() {
    try {
      const scripts = document.querySelectorAll('script');
      const graphqlIndicators = [/graphql/i, /__schema/i, /IntrospectionQuery/i];

      for (const script of scripts) {
        // Check src attribute
        if (script.src) {
          if (graphqlIndicators.some(p => p.test(script.src))) {
            this.technologies.push({ name: 'GraphQL (script src)', detected: true, source: script.src });
          }
          continue;
        }

        // Check inline content
        const content = script.textContent || '';
        if (content.length === 0 || content.length > 500000) continue;

        for (const pattern of graphqlIndicators) {
          if (pattern.test(content)) {
            this.technologies.push({ name: 'GraphQL (inline script)', detected: true, source: 'inline' });

            // Try to extract endpoint URLs from inline scripts
            const endpointPattern = /['"`]((?:https?:\/\/[^'"`\s]+|\/)[^'"`\s]*(?:graphql|gql)[^'"`\s]*)['"`]/gi;
            let match;
            while ((match = endpointPattern.exec(content)) !== null) {
              try {
                const resolved = new URL(match[1], window.location.href).href;
                this.endpoints.push({ url: resolved, source: 'inline-script' });
              } catch (e) { /* invalid URL */ }
            }
            break;
          }
        }
      }
    } catch (e) {
      console.error('Origami: GraphQL script tag detection error:', e.message);
    }
  }

  _detectFromMetaAndDataAttrs() {
    try {
      // Check meta tags
      const metas = document.querySelectorAll('meta');
      for (const meta of metas) {
        const content = meta.getAttribute('content') || '';
        const name = meta.getAttribute('name') || '';
        if (/graphql/i.test(content) || /graphql/i.test(name)) {
          try {
            const resolved = new URL(content, window.location.href).href;
            this.endpoints.push({ url: resolved, source: 'meta-tag' });
          } catch (e) { /* not a valid URL */ }
          this.technologies.push({ name: 'GraphQL (meta tag)', detected: true, source: name || 'meta' });
        }
      }

      // Check data attributes
      const elementsWithData = document.querySelectorAll('[data-graphql-endpoint], [data-graphql-url], [data-gql-endpoint]');
      for (const el of elementsWithData) {
        const value = el.getAttribute('data-graphql-endpoint') ||
                      el.getAttribute('data-graphql-url') ||
                      el.getAttribute('data-gql-endpoint');
        if (value) {
          try {
            const resolved = new URL(value, window.location.href).href;
            this.endpoints.push({ url: resolved, source: 'data-attribute' });
          } catch (e) { /* invalid URL */ }
        }
      }
    } catch (e) {
      console.error('Origami: GraphQL meta/data attribute detection error:', e.message);
    }
  }

  async introspect(endpoint) {
    const query = '{ __schema { queryType { name } mutationType { name } types { name kind fields { name type { name kind ofType { name kind } } args { name type { name kind } } } } } }';

    try {
      return await new Promise((resolve, reject) => {
        if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.sendMessage) {
          reject(new Error('Chrome runtime not available'));
          return;
        }

        chrome.runtime.sendMessage({
          action: 'graphqlProxy',
          url: endpoint,
          query: query,
          headers: { 'Content-Type': 'application/json' }
        }, (response) => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
            return;
          }
          if (!response || !response.success) {
            reject(new Error(response?.error || 'Introspection request failed'));
            return;
          }
          resolve(response.data);
        });
      });
    } catch (e) {
      console.log('Origami: GraphQL introspection skipped for ' + endpoint + ':', e.message);
      return null;
    }
  }

  analyzeSchema(schema) {
    this.issues = [];

    if (!schema || !schema.data || !schema.data.__schema) {
      // If we received a schema response at all, introspection is enabled
      if (schema && (schema.data || schema.errors)) {
        this.issues.push({
          severity: 'LOW',
          type: 'introspection-enabled',
          message: 'GraphQL introspection is enabled (schema response received but could not be fully parsed)',
          field: null,
          recommendation: 'Disable introspection in production environments to reduce attack surface'
        });
      }
      return this.issues;
    }

    const schemaData = schema.data.__schema;

    // Introspection enabled (the fact that we got a schema is itself a finding)
    this.issues.push({
      severity: 'LOW',
      type: 'introspection-enabled',
      message: 'GraphQL introspection is enabled in production',
      field: null,
      recommendation: 'Disable introspection in production environments to reduce attack surface'
    });

    const types = schemaData.types || [];
    const mutationTypeName = schemaData.mutationType ? schemaData.mutationType.name : null;

    // Analyze each type
    for (const type of types) {
      // Skip intrinsic GraphQL types
      if (type.name && type.name.startsWith('__')) continue;

      const fields = type.fields || [];

      for (const field of fields) {
        // Check for sensitive field names
        this._checkSensitiveFields(type.name, field);

        // Check for deeply nested types (potential N+1 DoS)
        this._checkNestedDepth(type.name, field, types, 0);

        // Check mutation fields for auth concerns
        if (type.name === mutationTypeName) {
          this._checkMutationAuth(field);
        }
      }
    }

    // Check for batch query support
    this._checkBatchQuerySupport(schemaData);

    // Deduplicate issues by type+field
    const seen = new Set();
    this.issues = this.issues.filter(issue => {
      const key = issue.type + ':' + (issue.field || '');
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    return this.issues;
  }

  _checkSensitiveFields(typeName, field) {
    const sensitivePatterns = [
      { pattern: /password/i, label: 'password' },
      { pattern: /secret/i, label: 'secret' },
      { pattern: /token/i, label: 'token' },
      { pattern: /\bssn\b/i, label: 'SSN' },
      { pattern: /credit[_-]?card/i, label: 'credit card' },
      { pattern: /\bemail\b/i, label: 'email' },
      { pattern: /\bphone\b/i, label: 'phone' }
    ];

    for (const { pattern, label } of sensitivePatterns) {
      if (pattern.test(field.name)) {
        this.issues.push({
          severity: 'HIGH',
          type: 'sensitive-field',
          message: 'Sensitive field "' + field.name + '" (' + label + ') exposed on type "' + typeName + '"',
          field: typeName + '.' + field.name,
          recommendation: 'Restrict access to sensitive fields using field-level authorization. Consider removing from the public schema.'
        });
      }
    }
  }

  _checkNestedDepth(typeName, field, allTypes, currentDepth, visited) {
    if (!visited) visited = new Set();

    if (currentDepth > 5) {
      this.issues.push({
        severity: 'LOW',
        type: 'deep-nesting',
        message: 'Deeply nested type detected (depth > 5) starting from "' + typeName + '.' + field.name + '" - potential N+1 query DoS',
        field: typeName + '.' + field.name,
        recommendation: 'Implement query depth limiting and query complexity analysis to prevent resource exhaustion'
      });
      return;
    }

    // Resolve the field type name (handle ofType for non-null and list wrappers)
    let fieldTypeName = null;
    if (field.type) {
      fieldTypeName = field.type.name;
      if (!fieldTypeName && field.type.ofType) {
        fieldTypeName = field.type.ofType.name;
      }
    }

    if (!fieldTypeName) return;

    // Cycle detection: skip types already in the current traversal path
    if (visited.has(fieldTypeName)) return;

    // Find the referenced type and recurse
    const referencedType = allTypes.find(t => t.name === fieldTypeName);
    if (referencedType && referencedType.fields && referencedType.kind === 'OBJECT') {
      visited.add(fieldTypeName);
      for (const nestedField of referencedType.fields) {
        this._checkNestedDepth(typeName, nestedField, allTypes, currentDepth + 1, visited);
      }
      visited.delete(fieldTypeName);
    }
  }

  _checkMutationAuth(field) {
    // Flag mutations that modify data -- these should have auth checks
    const dangerousPatterns = [
      /create/i, /update/i, /delete/i, /remove/i, /modify/i,
      /set/i, /add/i, /insert/i, /upsert/i, /destroy/i,
      /reset/i, /change/i, /grant/i, /revoke/i
    ];

    if (dangerousPatterns.some(p => p.test(field.name))) {
      this.issues.push({
        severity: 'MEDIUM',
        type: 'mutation-no-auth',
        message: 'Mutation "' + field.name + '" modifies data and may lack authorization checks',
        field: 'Mutation.' + field.name,
        recommendation: 'Ensure all data-modifying mutations require authentication and authorization. Implement field-level resolvers with auth checks.'
      });
    }
  }

  _checkBatchQuerySupport(schemaData) {
    // If there is a query type with multiple fields, batch queries are likely supported
    const queryTypeName = schemaData.queryType ? schemaData.queryType.name : null;
    if (!queryTypeName) return;

    const types = schemaData.types || [];
    const queryType = types.find(t => t.name === queryTypeName);

    if (queryType && queryType.fields && queryType.fields.length > 5) {
      this.issues.push({
        severity: 'LOW',
        type: 'batch-query',
        message: 'GraphQL schema exposes ' + queryType.fields.length + ' query fields -- batch queries may be possible without rate limiting',
        field: null,
        recommendation: 'Implement query complexity analysis and rate limiting per query to prevent batch abuse'
      });
    }
  }

  buildSchemaTree(schema) {
    this.schemaTree = [];

    if (!schema || !schema.data || !schema.data.__schema) {
      return this.schemaTree;
    }

    const schemaData = schema.data.__schema;
    const types = schemaData.types || [];
    const queryTypeName = schemaData.queryType ? schemaData.queryType.name : null;
    const mutationTypeName = schemaData.mutationType ? schemaData.mutationType.name : null;

    for (const type of types) {
      // Skip intrinsic types
      if (type.name && type.name.startsWith('__')) continue;
      if (type.kind === 'SCALAR' || type.kind === 'ENUM' || type.kind === 'INPUT_OBJECT') continue;

      const node = {
        name: type.name,
        kind: type.kind,
        isQuery: type.name === queryTypeName,
        isMutation: type.name === mutationTypeName,
        fields: []
      };

      for (const field of (type.fields || [])) {
        const fieldNode = {
          name: field.name,
          typeName: this._resolveTypeName(field.type),
          typeKind: field.type ? field.type.kind : null,
          args: (field.args || []).map(arg => ({
            name: arg.name,
            typeName: this._resolveTypeName(arg.type),
            typeKind: arg.type ? arg.type.kind : null
          }))
        };
        node.fields.push(fieldNode);
      }

      this.schemaTree.push(node);
    }

    // Sort: query type first, mutation type second, then alphabetical
    this.schemaTree.sort((a, b) => {
      if (a.isQuery) return -1;
      if (b.isQuery) return 1;
      if (a.isMutation) return -1;
      if (b.isMutation) return 1;
      return a.name.localeCompare(b.name);
    });

    return this.schemaTree;
  }

  _resolveTypeName(typeObj) {
    if (!typeObj) return 'Unknown';
    if (typeObj.name) return typeObj.name;
    if (typeObj.ofType) {
      const inner = typeObj.ofType.name || 'Unknown';
      if (typeObj.kind === 'NON_NULL') return inner + '!';
      if (typeObj.kind === 'LIST') return '[' + inner + ']';
      return inner;
    }
    return 'Unknown';
  }

  async analyze() {
    try {
      console.log('Origami: Starting GraphQL attack surface mapping');

      // Step 1: Detect endpoints and technologies
      const detection = this.detect();
      console.log('Origami: GraphQL detection found ' + detection.endpoints.length + ' endpoint(s), ' + detection.technologies.length + ' technology indicator(s)');

      // Step 2: Deduplicate endpoints by origin+basePath before introspection
      // Sites like LinkedIn have 20+ /graphql URLs that differ only by query params
      const uniqueByBase = new Map();
      for (const ep of this.endpoints) {
        try {
          const parsed = new URL(ep.url);
          const base = parsed.origin + parsed.pathname;
          if (!uniqueByBase.has(base)) {
            uniqueByBase.set(base, ep);
          }
        } catch (e) {
          // Keep malformed URLs as-is using the full URL as key
          if (!uniqueByBase.has(ep.url)) {
            uniqueByBase.set(ep.url, ep);
          }
        }
      }
      const dedupedEndpoints = Array.from(uniqueByBase.values());

      if (dedupedEndpoints.length < this.endpoints.length) {
        console.log('Origami: GraphQL deduped ' + this.endpoints.length + ' endpoints to ' + dedupedEndpoints.length + ' unique base paths');
      }

      // Step 3: Attempt introspection (max 3 endpoints, bail on repeated failures per origin)
      const MAX_INTROSPECTION_ATTEMPTS = 3;
      const failedOrigins = new Set();
      let introspectionResult = null;
      let attempts = 0;

      for (const endpoint of dedupedEndpoints) {
        if (attempts >= MAX_INTROSPECTION_ATTEMPTS) break;

        try {
          const origin = new URL(endpoint.url).origin;
          if (failedOrigins.has(origin)) continue;
        } catch (e) { /* proceed with introspection */ }

        attempts++;
        try {
          console.log('Origami: Attempting introspection on ' + endpoint.url);
          const result = await this.introspect(endpoint.url);
          if (result && (result.data || result.errors)) {
            introspectionResult = result;
            this.schema = result;
            break;
          }
        } catch (e) {
          console.log('Origami: Introspection failed for ' + endpoint.url + ': ' + e.message);
          try {
            failedOrigins.add(new URL(endpoint.url).origin);
          } catch (_) { /* ignore parse error */ }
        }
      }

      // Step 4: Analyze schema for security issues
      if (introspectionResult) {
        this.analyzeSchema(introspectionResult);
        this.buildSchemaTree(introspectionResult);
      }

      const results = {
        endpoints: this.endpoints,
        schema: this.schema,
        schemaTree: this.schemaTree,
        issues: this.issues,
        technologies: this.technologies
      };

      console.log('Origami: GraphQL mapping complete - ' + this.issues.length + ' issue(s) found');
      return results;
    } catch (e) {
      console.error('Origami: GraphQL analysis error:', e.message);
      return {
        endpoints: this.endpoints,
        schema: null,
        schemaTree: [],
        issues: [],
        technologies: this.technologies,
        error: e.message
      };
    }
  }
}

window.GraphQLMapper = GraphQLMapper;
