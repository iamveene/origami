// Google API Key Validator for Origami
// Ported from google_api_tester.py for use in Chrome extension

class GoogleAPIValidator {
  constructor(apiKey, referer = null) {
    this.apiKey = apiKey;
    this.referer = referer;
    this.results = [];
    this._extractedProjectNumber = null;
    // SECURITY NOTE: Testing API keys makes live requests to Google APIs from the user's IP.
    // This creates an attribution trail. Users should be aware that:
    // 1. Their IP is logged in the key owner's API usage logs
    // 2. Testing honeypot keys may reveal the investigator's IP
    // 3. Some tests consume quota on the key owner's account
    console.warn('Origami: GoogleAPIValidator creates live API requests. Use with caution on untrusted keys.');
  }

  async testAPI(service, url, options = {}) {
    const {
      method = 'GET',
      body = null,
      contentType = null,
      checkImage = false,
      checkQuota = true
    } = options;

    try {
      const headers = {};
      if (this.referer) {
        headers['Referer'] = this.referer;
      }
      if (contentType) {
        headers['Content-Type'] = contentType;
      }
      if (options.authHeader) {
        headers['Authorization'] = `key=${this.apiKey}`;
      }

      const fetchOptions = {
        method,
        headers,
        mode: 'cors'
      };

      // Use fetch referrer option as well — headers['Referer'] may be ignored
      // as a forbidden header in some contexts (service worker vs popup).
      if (this.referer) {
        fetchOptions.referrer = this.referer;
        fetchOptions.referrerPolicy = 'unsafe-url';
      }

      if (body) {
        fetchOptions.body = typeof body === 'string' ? body : JSON.stringify(body);
      }

      const response = await fetch(url, fetchOptions);
      const responseText = await response.text();

      // Check for referer blocking
      if (responseText.includes('API_KEY_HTTP_REFERRER_BLOCKED') ||
          responseText.includes('Requests from referer') ||
          responseText.includes('did not specify any referer')) {
        return {
          service,
          status: 'ENABLED (Referer Restricted)',
          code: response.status,
          message: 'API enabled but blocked by HTTP referer restriction'
        };
      }

      // Check for image response
      if (checkImage && response.status === 200 &&
          response.headers.get('content-type')?.includes('image')) {
        const result = {
          service,
          status: 'ENABLED',
          code: 200,
          message: 'API is enabled and working'
        };
        if (this.referer) result.refererRequired = true;
        return result;
      }

      // Check for success
      if (response.status === 200) {
        const result = {
          service,
          status: 'ENABLED',
          code: 200,
          message: 'API is enabled and working'
        };
        if (this.referer) result.refererRequired = true;
        return result;
      }

      // Check for quota exceeded
      if (checkQuota && (responseText.includes('quotaExceeded') ||
          responseText.includes('OVER_QUERY_LIMIT'))) {
        const result = {
          service,
          status: 'ENABLED (Quota Exceeded)',
          code: response.status,
          message: 'API enabled but quota exceeded'
        };
        if (this.referer) result.refererRequired = true;
        return result;
      }

      // Check for API key restriction patterns (key is valid but restricted)
      if (responseText.includes('API_KEY_ANDROID_APP_BLOCKED')) {
        return {
          service,
          status: 'ENABLED (Android Restricted)',
          code: response.status,
          message: 'API enabled but restricted to specific Android apps'
        };
      }

      if (responseText.includes('API_KEY_IOS_APP_BLOCKED')) {
        return {
          service,
          status: 'ENABLED (iOS Restricted)',
          code: response.status,
          message: 'API enabled but restricted to specific iOS apps'
        };
      }

      if (responseText.includes('API_KEY_IP_ADDRESS_BLOCKED') ||
          responseText.includes('ipDeniedByGfe') ||
          responseText.includes('IP address is blocked')) {
        return {
          service,
          status: 'ENABLED (IP Restricted)',
          code: response.status,
          message: 'API enabled but restricted to specific IP addresses'
        };
      }

      if (responseText.includes('accessNotConfigured') ||
          responseText.includes('has not been used in project') ||
          responseText.includes('it is disabled') ||
          responseText.includes('is not activated')) {
        return {
          service,
          status: 'NOT_ACTIVATED',
          code: response.status,
          message: 'API key valid but this specific API is not enabled for the project'
        };
      }

      // Parse JSON error - sanitize response content to prevent XSS
      try {
        const jsonResponse = JSON.parse(responseText);
        const rawMessage = jsonResponse.error?.message ||
                           jsonResponse.error_message ||
                           jsonResponse.status ||
                           'Unknown error';
        // Strip any HTML tags from error messages to prevent injection
        const errorMessage = String(rawMessage).replace(/<[^>]*>/g, '').substring(0, 200);

        // Extract project number from error messages (e.g., "project 836575658406")
        if (!this._extractedProjectNumber) {
          const projectMatch = String(rawMessage).match(/project\s+(\d{6,})\b/);
          if (projectMatch) {
            this._extractedProjectNumber = projectMatch[1];
          }
        }

        return {
          service,
          status: 'DISABLED',
          code: response.status,
          message: errorMessage
        };
      } catch {
        // Extract project number from non-JSON responses too
        if (!this._extractedProjectNumber) {
          const projectMatch = responseText.match(/project\s+(\d{6,})\b/);
          if (projectMatch) {
            this._extractedProjectNumber = projectMatch[1];
          }
        }

        return {
          service,
          status: 'DISABLED',
          code: response.status,
          message: responseText.replace(/<[^>]*>/g, '').substring(0, 100)
        };
      }
    } catch (error) {
      return {
        service,
        status: 'ERROR',
        code: 0,
        message: error.message
      };
    }
  }

  async testYouTubeAPI() {
    const url = `https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&key=${this.apiKey}`;
    return this.testAPI('YouTube Data API', url);
  }

  async testMapsStaticAPI() {
    const url = `https://maps.googleapis.com/maps/api/staticmap?center=45.5,10.5&zoom=7&size=400x400&key=${this.apiKey}`;
    return this.testAPI('Maps Static API', url, { checkImage: true });
  }

  async testGeolocationAPI() {
    const url = `https://www.googleapis.com/geolocation/v1/geolocate?key=${this.apiKey}`;
    return this.testAPI('Geolocation API', url, { method: 'POST' });
  }

  async testCustomSearchAPI() {
    const url = `https://www.googleapis.com/customsearch/v1?q=test&key=${this.apiKey}`;
    return this.testAPI('Custom Search API', url);
  }

  async testFirebaseAuthAPI() {
    const url = `https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${this.apiKey}`;

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ returnSecureToken: true })
      });
      const data = await response.json();

      if (response.status === 200 && data.idToken) {
        return {
          service: 'Firebase Auth (Identity Toolkit)',
          status: 'ENABLED',
          code: 200,
          message: 'Anonymous signup enabled - obtained idToken',
          impact: 'CRITICAL',
          cost: 'LOW',
          anonymousToken: data.idToken,
          localId: data.localId,
          details: { authType: 'anonymous', tokenObtained: true }
        };
      }

      if (response.status === 400) {
        const errorCode = data.error?.message || '';
        if (errorCode.includes('ADMIN_ONLY_OPERATION')) {
          return { service: 'Firebase Auth (Identity Toolkit)', status: 'ENABLED (Signup Disabled)', code: 400,
            message: 'API active but anonymous/email signup disabled by admin', impact: 'LOW', cost: 'LOW' };
        }
        return { service: 'Firebase Auth (Identity Toolkit)', status: 'ENABLED', code: 400,
          message: 'API enabled (anonymous auth may be disabled)', impact: 'HIGH', cost: 'LOW' };
      }

      // Check for restriction patterns in Firebase Auth error
      const errorRaw = data.error?.message || '';
      if (errorRaw.includes('API_KEY_HTTP_REFERRER_BLOCKED') || errorRaw.includes('Requests from referer')) {
        return { service: 'Firebase Auth (Identity Toolkit)', status: 'ENABLED (Referer Restricted)', code: response.status,
          message: 'API enabled but blocked by HTTP referer restriction', impact: 'LOW', cost: 'LOW' };
      }
      if (errorRaw.includes('API_KEY_ANDROID_APP_BLOCKED')) {
        return { service: 'Firebase Auth (Identity Toolkit)', status: 'ENABLED (Android Restricted)', code: response.status,
          message: 'API enabled but restricted to specific Android apps', impact: 'LOW', cost: 'LOW' };
      }
      if (errorRaw.includes('API_KEY_IOS_APP_BLOCKED')) {
        return { service: 'Firebase Auth (Identity Toolkit)', status: 'ENABLED (iOS Restricted)', code: response.status,
          message: 'API enabled but restricted to specific iOS apps', impact: 'LOW', cost: 'LOW' };
      }
      if (errorRaw.includes('API_KEY_IP_ADDRESS_BLOCKED') || errorRaw.includes('ipDeniedByGfe')) {
        return { service: 'Firebase Auth (Identity Toolkit)', status: 'ENABLED (IP Restricted)', code: response.status,
          message: 'API enabled but restricted to specific IP addresses', impact: 'LOW', cost: 'LOW' };
      }
      if (errorRaw.includes('has not been used in project') || errorRaw.includes('it is disabled') || errorRaw.includes('accessNotConfigured')) {
        if (!this._extractedProjectNumber) {
          const projectMatch = String(errorRaw).match(/project\s+(\d{6,})\b/);
          if (projectMatch) this._extractedProjectNumber = projectMatch[1];
        }
        return { service: 'Firebase Auth (Identity Toolkit)', status: 'NOT_ACTIVATED', code: response.status,
          message: 'API key valid but Identity Toolkit is not enabled for the project', impact: 'LOW', cost: 'LOW' };
      }

      const errorMsg = errorRaw || 'API key not valid for Identity Toolkit';
      if (!this._extractedProjectNumber) {
        const projectMatch = String(errorMsg).match(/project\s+(\d{6,})\b/);
        if (projectMatch) this._extractedProjectNumber = projectMatch[1];
      }
      return { service: 'Firebase Auth (Identity Toolkit)', status: 'DISABLED', code: response.status,
        message: errorMsg, impact: 'LOW', cost: 'LOW' };
    } catch (error) {
      return { service: 'Firebase Auth (Identity Toolkit)', status: 'ERROR', code: 0, message: error.message };
    }
  }

  async testFirebaseRealtimeDB(projectId, idToken = null) {
    if (!projectId) {
      return {
        service: 'Firebase Realtime Database',
        status: 'SKIPPED',
        message: 'Requires project ID (extract from Firebase config or run Resource Manager)',
        impact: 'CRITICAL',
        cost: 'LOW'
      };
    }

    const urls = [
      `https://${projectId}-default-rtdb.firebaseio.com/.json`,
      `https://${projectId}.firebaseio.com/.json`
    ];

    for (const dbUrl of urls) {
      try {
        // Step 1: Unauthenticated access
        const response = await fetch(dbUrl);
        if (response.status === 200) {
          const data = await response.json();
          if (data !== null) {
            // Fully open database
            let topLevelKeys = [];
            try {
              const shallowResp = await fetch(dbUrl.replace('.json', '.json?shallow=true'));
              if (shallowResp.status === 200) {
                const shallowData = await shallowResp.json();
                topLevelKeys = shallowData ? Object.keys(shallowData) : [];
              }
            } catch (e) { /* shallow query failed, not critical */ }

            return {
              service: 'Firebase Realtime Database',
              status: 'ENABLED',
              code: 200,
              message: `Database is publicly readable without authentication`,
              impact: 'CRITICAL',
              cost: 'LOW',
              details: { accessLevel: 'OPEN', topLevelKeys, databaseUrl: dbUrl.replace('/.json', '') }
            };
          }
        }

        // Step 2: Authenticated access (if we have a token)
        if ((response.status === 401 || response.status === 403) && idToken) {
          const authResponse = await fetch(`${dbUrl}?auth=${idToken}`);
          if (authResponse.status === 200) {
            const authData = await authResponse.json();
            if (authData !== null) {
              let topLevelKeys = [];
              try {
                const shallowResp = await fetch(`${dbUrl.replace('.json', '.json')}?shallow=true&auth=${idToken}`);
                if (shallowResp.status === 200) {
                  const shallowData = await shallowResp.json();
                  topLevelKeys = shallowData ? Object.keys(shallowData) : [];
                }
              } catch (e) { /* shallow query failed */ }

              return {
                service: 'Firebase Realtime Database',
                status: 'ENABLED',
                code: 200,
                message: 'Database readable with anonymous auth token (auth != null misconfiguration)',
                impact: 'HIGH',
                cost: 'LOW',
                details: { accessLevel: 'AUTHENTICATED', topLevelKeys, databaseUrl: dbUrl.replace('/.json', '') }
              };
            }
          }
        }

        // If we got a 404, this URL variant doesn't exist -- try the next one
        if (response.status === 404) continue;

        // If we got 401/403 without a token or auth also failed, DB is secured
        return {
          service: 'Firebase Realtime Database',
          status: 'DISABLED',
          code: response.status,
          message: 'Database properly secured (requires valid authentication)',
          impact: 'LOW',
          cost: 'LOW',
          details: { accessLevel: 'SECURED', databaseUrl: dbUrl.replace('/.json', '') }
        };
      } catch (error) {
        // Network error on this URL -- try the next variant
        continue;
      }
    }

    return {
      service: 'Firebase Realtime Database',
      status: 'ERROR',
      code: 0,
      message: 'Could not reach any database URL for this project',
      impact: 'LOW',
      cost: 'LOW'
    };
  }

  async testFirestoreAPI(projectId) {
    if (!projectId) {
      return {
        service: 'Cloud Firestore',
        status: 'SKIPPED',
        message: 'Requires project ID',
        impact: 'CRITICAL',
        cost: 'LOW'
      };
    }

    const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents?key=${this.apiKey}`;
    try {
      const response = await fetch(url);
      if (response.status === 200) {
        const data = await response.json();
        const collections = (data.documents || []).map(d => {
          const parts = d.name.split('/');
          // Collection is the second-to-last path segment
          return parts.length >= 2 ? parts[parts.length - 2] : d.name;
        });
        const uniqueCollections = [...new Set(collections)];
        return {
          service: 'Cloud Firestore',
          status: 'ENABLED',
          code: 200,
          message: `Firestore publicly readable - found ${uniqueCollections.length} collection(s)`,
          impact: 'CRITICAL',
          cost: 'LOW',
          details: { collections: uniqueCollections }
        };
      }
      return {
        service: 'Cloud Firestore',
        status: 'DISABLED',
        code: response.status,
        message: 'Firestore properly secured',
        impact: 'LOW',
        cost: 'LOW'
      };
    } catch (error) {
      return { service: 'Cloud Firestore', status: 'ERROR', code: 0, message: error.message };
    }
  }

  async testFirebaseStorageBucket(projectId) {
    if (!projectId) {
      return {
        service: 'Firebase Storage',
        status: 'SKIPPED',
        message: 'Requires project ID',
        impact: 'HIGH',
        cost: 'LOW'
      };
    }

    const url = `https://firebasestorage.googleapis.com/v0/b/${projectId}.appspot.com/o?maxResults=10`;
    try {
      const response = await fetch(url);
      if (response.status === 200) {
        const data = await response.json();
        const items = data.items || [];
        if (items.length > 0) {
          const sampleFiles = items.slice(0, 5).map(i => i.name);
          return {
            service: 'Firebase Storage',
            status: 'ENABLED',
            code: 200,
            message: `Storage bucket publicly listable - ${items.length} file(s) found`,
            impact: 'HIGH',
            cost: 'LOW',
            details: { itemCount: items.length, sampleFiles }
          };
        }
        return {
          service: 'Firebase Storage',
          status: 'ENABLED',
          code: 200,
          message: 'Storage bucket accessible but empty',
          impact: 'MEDIUM',
          cost: 'LOW'
        };
      }
      return {
        service: 'Firebase Storage',
        status: 'DISABLED',
        code: response.status,
        message: 'Storage bucket properly secured',
        impact: 'LOW',
        cost: 'LOW'
      };
    } catch (error) {
      return { service: 'Firebase Storage', status: 'ERROR', code: 0, message: error.message };
    }
  }

  async testFirebaseSuite(projectId) {
    // Auth runs first (sequential dependency for idToken)
    const authResult = await this.testFirebaseAuthAPI();
    const idToken = authResult.anonymousToken || null;

    const results = [authResult];

    if (projectId) {
      const [dbResult, firestoreResult, storageResult] = await Promise.all([
        this.testFirebaseRealtimeDB(projectId, idToken),
        this.testFirestoreAPI(projectId),
        this.testFirebaseStorageBucket(projectId)
      ]);
      results.push(dbResult, firestoreResult, storageResult);
    }

    return results;
  }

  async testTranslationAPI() {
    const url = `https://translation.googleapis.com/language/translate/v2?key=${this.apiKey}&q=hello&target=es`;
    return this.testAPI('Cloud Translation API', url);
  }

  async testBooksAPI() {
    const url = `https://www.googleapis.com/books/v1/volumes?q=test&key=${this.apiKey}`;
    return this.testAPI('Books API', url);
  }

  async testTimezoneAPI() {
    const url = `https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key=${this.apiKey}`;
    return this.testAPI('Timezone API', url);
  }

  async testDirectionsAPI() {
    const url = `https://maps.googleapis.com/maps/api/directions/json?origin=Toronto&destination=Montreal&key=${this.apiKey}`;
    return this.testAPI('Directions API', url);
  }

  async testPlacesAPI() {
    const url = `https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=-33.8670,151.1957&radius=500&type=restaurant&key=${this.apiKey}`;
    return this.testAPI('Places API', url);
  }

  async testGeocodingAPI() {
    const url = `https://maps.googleapis.com/maps/api/geocode/json?address=1600+Amphitheatre+Parkway,+Mountain+View,+CA&key=${this.apiKey}`;
    return this.testAPI('Geocoding API', url);
  }

  async testDistanceMatrixAPI() {
    const url = `https://maps.googleapis.com/maps/api/distancematrix/json?origins=Vancouver+BC&destinations=San+Francisco&key=${this.apiKey}`;
    return this.testAPI('Distance Matrix API', url);
  }

  async testElevationAPI() {
    const url = `https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key=${this.apiKey}`;
    return this.testAPI('Elevation API', url);
  }

  async testPageSpeedAPI() {
    const url = `https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=https://www.google.com&key=${this.apiKey}`;
    return this.testAPI('PageSpeed Insights API', url);
  }

  async testFontsAPI() {
    const url = `https://www.googleapis.com/webfonts/v1/webfonts?key=${this.apiKey}`;
    return this.testAPI('Google Fonts API', url);
  }

  // ===== AI/ML APIs (High Cost) =====

  async testVertexAIAPI() {
    // Test Vertex AI by listing available models (doesn't require project ID)
    const url = `https://generativelanguage.googleapis.com/v1/models?key=${this.apiKey}`;
    const result = await this.testAPI('Vertex AI / AI Platform', url);
    return { ...result, impact: 'CRITICAL', cost: 'VERY_HIGH' };
  }

  async testGeminiAPI() {
    // Test Gemini API with minimal text generation request
    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${this.apiKey}`;
    const body = {
      contents: [{
        parts: [{ text: "Hi" }]
      }]
    };
    const result = await this.testAPI('Generative AI (Gemini)', url, {
      method: 'POST',
      body,
      contentType: 'application/json'
    });
    return { ...result, impact: 'CRITICAL', cost: 'VERY_HIGH' };
  }

  async testVisionAPI() {
    // Test Vision API with minimal image annotation request
    // Using a 1x1 red pixel base64 encoded
    const url = `https://vision.googleapis.com/v1/images:annotate?key=${this.apiKey}`;
    const body = {
      requests: [{
        image: {
          content: 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg=='
        },
        features: [{ type: 'LABEL_DETECTION', maxResults: 1 }]
      }]
    };
    const result = await this.testAPI('Cloud Vision API', url, {
      method: 'POST',
      body,
      contentType: 'application/json'
    });
    return { ...result, impact: 'HIGH', cost: 'HIGH' };
  }

  async testSpeechAPI() {
    // Test Speech-to-Text with minimal audio request
    const url = `https://speech.googleapis.com/v1/speech:recognize?key=${this.apiKey}`;
    const body = {
      config: {
        encoding: 'LINEAR16',
        sampleRateHertz: 16000,
        languageCode: 'en-US'
      },
      audio: {
        content: 'UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQAAAAA=' // Empty WAV
      }
    };
    const result = await this.testAPI('Speech-to-Text API', url, {
      method: 'POST',
      body,
      contentType: 'application/json'
    });
    return { ...result, impact: 'HIGH', cost: 'VERY_HIGH' };
  }

  async testVideoIntelligenceAPI() {
    // Test Video Intelligence with minimal request
    const url = `https://videointelligence.googleapis.com/v1/videos:annotate?key=${this.apiKey}`;
    const body = {
      inputUri: 'gs://cloud-samples-data/video/cat.mp4',
      features: ['LABEL_DETECTION']
    };
    const result = await this.testAPI('Video Intelligence API', url, {
      method: 'POST',
      body,
      contentType: 'application/json'
    });
    return { ...result, impact: 'HIGH', cost: 'VERY_HIGH' };
  }

  async testNaturalLanguageAPI() {
    // Test Natural Language API with minimal text analysis
    const url = `https://language.googleapis.com/v1/documents:analyzeEntities?key=${this.apiKey}`;
    const body = {
      document: {
        type: 'PLAIN_TEXT',
        content: 'test'
      },
      encodingType: 'UTF8'
    };
    const result = await this.testAPI('Natural Language API', url, {
      method: 'POST',
      body,
      contentType: 'application/json'
    });
    return { ...result, impact: 'HIGH', cost: 'HIGH' };
  }

  async testTextToSpeechAPI() {
    // Test Text-to-Speech with minimal synthesis request
    const url = `https://texttospeech.googleapis.com/v1/text:synthesize?key=${this.apiKey}`;
    const body = {
      input: { text: 'hi' },
      voice: { languageCode: 'en-US', name: 'en-US-Standard-A' },
      audioConfig: { audioEncoding: 'MP3' }
    };
    const result = await this.testAPI('Text-to-Speech API', url, {
      method: 'POST',
      body,
      contentType: 'application/json'
    });
    return { ...result, impact: 'MEDIUM', cost: 'HIGH' };
  }

  // ===== GCP Infrastructure APIs (High Reconnaissance Value) =====

  async _probeProjectNumber() {
    if (this._extractedProjectNumber) return this._extractedProjectNumber;
    // Lightweight probe: Books API is free and reliably leaks project number in error messages
    const url = `https://www.googleapis.com/books/v1/volumes?q=test&key=${this.apiKey}`;
    try {
      const response = await fetch(url);
      const text = await response.text();
      const match = text.match(/project\s+(\d{6,})\b/);
      if (match) {
        this._extractedProjectNumber = match[1];
        return match[1];
      }
    } catch {}
    return null;
  }

  async discoverProjectIds() {
    // Discover accessible GCP project IDs via Resource Manager API
    const url = `https://cloudresourcemanager.googleapis.com/v1/projects?key=${this.apiKey}`;
    try {
      const response = await fetch(url);
      if (response.status === 200) {
        const data = await response.json();
        const projects = data.projects || [];
        return projects.map(p => ({
          projectId: p.projectId,
          projectName: p.name,
          projectNumber: p.projectNumber,
          lifecycleState: p.lifecycleState
        }));
      }
      return [];
    } catch (error) {
      console.error('Project discovery failed:', error);
      return [];
    }
  }

  async testResourceManagerAPI() {
    // Test Resource Manager API (project listing)
    const url = `https://cloudresourcemanager.googleapis.com/v1/projects?key=${this.apiKey}`;
    const result = await this.testAPI('Cloud Resource Manager', url);

    // If enabled, discover and include project IDs
    if (result.status === 'ENABLED') {
      const projects = await this.discoverProjectIds();
      result.discoveredProjects = projects;
      result.message = `API enabled - discovered ${projects.length} project(s)`;
    }

    return { ...result, impact: 'CRITICAL', cost: 'LOW' };
  }

  async testComputeEngineAPI(projectId = null) {
    if (!projectId) {
      return {
        service: 'Compute Engine API',
        status: 'SKIPPED',
        message: 'Requires project ID or number (none extractable from API responses)',
        impact: 'CRITICAL',
        cost: 'LOW'
      };
    }

    // Use aggregated list to check all zones at once
    const url = `https://compute.googleapis.com/compute/v1/projects/${projectId}/aggregated/instances?key=${this.apiKey}`;
    const result = await this.testAPI('Compute Engine API', url);
    return { ...result, impact: 'CRITICAL', cost: 'LOW', projectId };
  }

  async testCloudStorageAPI(projectId = null) {
    if (!projectId) {
      return {
        service: 'Cloud Storage API',
        status: 'SKIPPED',
        message: 'Requires project ID or number (none extractable from API responses)',
        impact: 'CRITICAL',
        cost: 'LOW'
      };
    }

    const url = `https://storage.googleapis.com/storage/v1/b?project=${projectId}&key=${this.apiKey}`;
    const result = await this.testAPI('Cloud Storage API', url);
    return { ...result, impact: 'CRITICAL', cost: 'LOW', projectId };
  }

  async testSecretManagerAPI(projectId = null) {
    if (!projectId) {
      return {
        service: 'Secret Manager API',
        status: 'SKIPPED',
        message: 'Requires project ID or number (none extractable from API responses)',
        impact: 'CRITICAL',
        cost: 'LOW'
      };
    }

    const url = `https://secretmanager.googleapis.com/v1/projects/${projectId}/secrets?key=${this.apiKey}`;
    const result = await this.testAPI('Secret Manager API', url);
    return { ...result, impact: 'CRITICAL', cost: 'LOW', projectId };
  }

  async testBigQueryAPI(projectId = null) {
    if (!projectId) {
      return {
        service: 'BigQuery API',
        status: 'SKIPPED',
        message: 'Requires project ID or number (none extractable from API responses)',
        impact: 'HIGH',
        cost: 'MEDIUM'
      };
    }

    const url = `https://bigquery.googleapis.com/bigquery/v2/projects/${projectId}/datasets?key=${this.apiKey}`;
    const result = await this.testAPI('BigQuery API', url);
    return { ...result, impact: 'HIGH', cost: 'MEDIUM', projectId };
  }

  // Quick tests - faster subset for auto-validation
  async runQuickTests() {
    const tests = [
      this.testYouTubeAPI(),
      this.testGeocodingAPI(),
      this.testTranslationAPI(),
      this.testBooksAPI(),
      this.testFontsAPI()
    ];

    return await Promise.all(tests);
  }

  // Full test suite (all 30 APIs)
  async runAllTests() {
    // Phase 1: Resource Manager + Firebase Auth + all non-infra tests
    const resourceManagerResult = await this.testResourceManagerAPI();
    const discoveredProjects = resourceManagerResult.discoveredProjects || [];
    let projectId = discoveredProjects.length > 0 ? discoveredProjects[0].projectId : null;

    const firebaseAuthResult = await this.testFirebaseAuthAPI();
    const idToken = firebaseAuthResult.anonymousToken || null;

    const phase1Tests = [
      this.testYouTubeAPI(),
      this.testMapsStaticAPI(),
      this.testGeolocationAPI(),
      this.testCustomSearchAPI(),
      this.testTranslationAPI(),
      this.testBooksAPI(),
      this.testTimezoneAPI(),
      this.testDirectionsAPI(),
      this.testPlacesAPI(),
      this.testGeocodingAPI(),
      this.testDistanceMatrixAPI(),
      this.testElevationAPI(),
      this.testPageSpeedAPI(),
      this.testFontsAPI(),
      this.testVertexAIAPI(),
      this.testGeminiAPI(),
      this.testVisionAPI(),
      this.testSpeechAPI(),
      this.testVideoIntelligenceAPI(),
      this.testNaturalLanguageAPI(),
      this.testTextToSpeechAPI()
    ];

    const phase1Results = await Promise.all(phase1Tests);

    // Phase 2: Use discovered project ID, or fall back to project number extracted from error messages
    const projectIdentifier = projectId || this._extractedProjectNumber;

    const phase2Tests = [
      this.testComputeEngineAPI(projectIdentifier),
      this.testCloudStorageAPI(projectIdentifier),
      this.testSecretManagerAPI(projectIdentifier),
      this.testBigQueryAPI(projectIdentifier),
      // Firebase hostname-based services need string project ID, not a number
      this.testFirebaseRealtimeDB(projectId || this._firebaseProjectId, idToken),
      this.testFirestoreAPI(projectIdentifier),
      this.testFirebaseStorageBucket(projectId || this._firebaseProjectId)
    ];

    const phase2Results = await Promise.all(phase2Tests);

    return [resourceManagerResult, firebaseAuthResult, ...phase1Results, ...phase2Results];
  }

  // Run selected tests based on service IDs (new granular testing)
  async runSelectedTests(selectedServiceIds, discoveredProjects = []) {
    let projectId = discoveredProjects.length > 0 ? discoveredProjects[0].projectId : null;

    const infraServices = new Set(['compute-engine', 'cloud-storage', 'secret-manager', 'bigquery']);
    const firebaseDbServices = new Set(['firebase-realtime-db', 'firebase-firestore', 'firebase-storage']);
    const projectDependentServices = new Set([...infraServices, ...firebaseDbServices]);
    const sequentialIds = new Set(['resource-manager', 'firebase-auth']);

    // Service map for non-project-dependent tests
    const serviceMap = {
      'youtube': () => this.testYouTubeAPI(),
      'maps-static': () => this.testMapsStaticAPI(),
      'geolocation': () => this.testGeolocationAPI(),
      'custom-search': () => this.testCustomSearchAPI(),
      'translation': () => this.testTranslationAPI(),
      'books': () => this.testBooksAPI(),
      'timezone': () => this.testTimezoneAPI(),
      'directions': () => this.testDirectionsAPI(),
      'places': () => this.testPlacesAPI(),
      'geocoding': () => this.testGeocodingAPI(),
      'distance-matrix': () => this.testDistanceMatrixAPI(),
      'elevation': () => this.testElevationAPI(),
      'pagespeed': () => this.testPageSpeedAPI(),
      'fonts': () => this.testFontsAPI(),
      'vertex-ai': () => this.testVertexAIAPI(),
      'gemini': () => this.testGeminiAPI(),
      'vision': () => this.testVisionAPI(),
      'speech': () => this.testSpeechAPI(),
      'video-intelligence': () => this.testVideoIntelligenceAPI(),
      'natural-language': () => this.testNaturalLanguageAPI(),
      'text-to-speech': () => this.testTextToSpeechAPI(),
      'resource-manager': () => this.testResourceManagerAPI()
    };

    // --- Sequential: Resource Manager (if selected) ---
    let savedResourceManagerResult = null;
    if (selectedServiceIds.includes('resource-manager')) {
      savedResourceManagerResult = await this.testResourceManagerAPI();
      if (savedResourceManagerResult.discoveredProjects && savedResourceManagerResult.discoveredProjects.length > 0) {
        projectId = savedResourceManagerResult.discoveredProjects[0].projectId;
      }
    }

    // --- Sequential: Firebase Auth (if needed for idToken) ---
    const hasFirebaseDb = selectedServiceIds.some(id => firebaseDbServices.has(id));
    const hasFirebaseAuth = selectedServiceIds.includes('firebase-auth');
    let savedFirebaseAuthResult = null;
    let firebaseIdToken = null;

    if (hasFirebaseAuth || hasFirebaseDb) {
      savedFirebaseAuthResult = await this.testFirebaseAuthAPI();
      firebaseIdToken = savedFirebaseAuthResult.anonymousToken || null;
    }

    // --- Phase 1: All non-project-dependent tests in parallel ---
    const phase1Ids = selectedServiceIds.filter(id => !sequentialIds.has(id) && !projectDependentServices.has(id));
    const phase1Tests = phase1Ids
      .map(id => {
        if (!serviceMap[id]) {
          console.warn(`Unknown service ID: ${id}`);
          return null;
        }
        return serviceMap[id]();
      })
      .filter(test => test !== null);

    const phase1Results = await Promise.all(phase1Tests);

    // --- Resolve project identifier for Phase 2 ---
    // Prefer discovered project ID (string), fall back to project number extracted from error messages
    const hasInfraTests = selectedServiceIds.some(id => projectDependentServices.has(id));
    if (!projectId && hasInfraTests && !this._extractedProjectNumber) {
      // No project number extracted from Phase 1 (e.g., only infra tests selected) -- run a probe
      if (phase1Ids.length === 0) {
        await this._probeProjectNumber();
      }
    }
    const projectIdentifier = projectId || this._extractedProjectNumber;

    // --- Phase 2: Project-dependent tests in parallel ---
    const phase2Ids = selectedServiceIds.filter(id => projectDependentServices.has(id));
    const phase2Tests = phase2Ids.map(id => {
      if (infraServices.has(id) || id === 'firebase-firestore') {
        // GCP APIs accept project number in URL paths
        if (id === 'compute-engine') return this.testComputeEngineAPI(projectIdentifier);
        if (id === 'cloud-storage') return this.testCloudStorageAPI(projectIdentifier);
        if (id === 'secret-manager') return this.testSecretManagerAPI(projectIdentifier);
        if (id === 'bigquery') return this.testBigQueryAPI(projectIdentifier);
        if (id === 'firebase-firestore') return this.testFirestoreAPI(projectIdentifier);
      }
      // Firebase hostname-based services need string project ID, not a number
      if (id === 'firebase-realtime-db') return this.testFirebaseRealtimeDB(projectId || this._firebaseProjectId, firebaseIdToken);
      if (id === 'firebase-storage') return this.testFirebaseStorageBucket(projectId || this._firebaseProjectId);
      return null;
    }).filter(test => test !== null);

    const phase2Results = await Promise.all(phase2Tests);

    // Prepend sequential results
    const prefixResults = [];
    if (savedResourceManagerResult) prefixResults.push(savedResourceManagerResult);
    if (savedFirebaseAuthResult && hasFirebaseAuth) prefixResults.push(savedFirebaseAuthResult);

    return [...prefixResults, ...phase1Results, ...phase2Results];
  }
}

// Export for use in extension
if (typeof module !== 'undefined' && module.exports) {
  module.exports = GoogleAPIValidator;
}

