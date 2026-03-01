// Google API Key Validator for Origami
// Ported from google_api_tester.py for use in Chrome extension

class GoogleAPIValidator {
  constructor(apiKey, referer = null) {
    this.apiKey = apiKey;
    this.referer = referer;
    this.results = [];
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

      if (body) {
        fetchOptions.body = typeof body === 'string' ? body : JSON.stringify(body);
      }

      const response = await fetch(url, fetchOptions);
      const responseText = await response.text();

      // Check for referer blocking
      if (responseText.includes('API_KEY_HTTP_REFERRER_BLOCKED') || 
          responseText.includes('Requests from referer')) {
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
        return {
          service,
          status: 'ENABLED',
          code: 200,
          message: 'API is enabled and working'
        };
      }

      // Check for success
      if (response.status === 200) {
        return {
          service,
          status: 'ENABLED',
          code: 200,
          message: 'API is enabled and working'
        };
      }

      // Check for quota exceeded
      if (checkQuota && (responseText.includes('quotaExceeded') || 
          responseText.includes('OVER_QUERY_LIMIT'))) {
        return {
          service,
          status: 'ENABLED (Quota Exceeded)',
          code: response.status,
          message: 'API enabled but quota exceeded'
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

        return {
          service,
          status: 'DISABLED',
          code: response.status,
          message: errorMessage
        };
      } catch {
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

  async testFCMAPI() {
    const url = 'https://fcm.googleapis.com/fcm/send';
    const result = await this.testAPI('Firebase Cloud Messaging', url, { 
      method: 'POST',
      authHeader: true
    });
    
    // FCM returns 400 if enabled but request invalid (expected)
    if (result.code === 400) {
      return {
        ...result,
        status: 'ENABLED',
        message: 'API is enabled (invalid request expected)'
      };
    }
    return result;
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
    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=${this.apiKey}`;
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
        message: 'Requires project ID (run Resource Manager first)',
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
        message: 'Requires project ID (run Resource Manager first)',
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
        message: 'Requires project ID (run Resource Manager first)',
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
        message: 'Requires project ID (run Resource Manager first)',
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

  // Full test suite (all 27 APIs)
  async runAllTests() {
    // First test Resource Manager to discover project IDs
    const resourceManagerResult = await this.testResourceManagerAPI();
    const discoveredProjects = resourceManagerResult.discoveredProjects || [];
    const projectId = discoveredProjects.length > 0 ? discoveredProjects[0].projectId : null;

    // Run all tests (infrastructure tests will use discovered project ID)
    const tests = [
      // Original 15 APIs
      this.testYouTubeAPI(),
      this.testMapsStaticAPI(),
      this.testGeolocationAPI(),
      this.testCustomSearchAPI(),
      this.testFCMAPI(),
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
      // New AI/ML APIs (7)
      this.testVertexAIAPI(),
      this.testGeminiAPI(),
      this.testVisionAPI(),
      this.testSpeechAPI(),
      this.testVideoIntelligenceAPI(),
      this.testNaturalLanguageAPI(),
      this.testTextToSpeechAPI(),
      // New Infrastructure APIs (5) - use discovered project ID
      this.testComputeEngineAPI(projectId),
      this.testCloudStorageAPI(projectId),
      this.testSecretManagerAPI(projectId),
      this.testBigQueryAPI(projectId)
    ];

    const results = await Promise.all(tests);

    // Add Resource Manager result to the beginning
    return [resourceManagerResult, ...results];
  }

  // Run selected tests based on service IDs (new granular testing)
  async runSelectedTests(selectedServiceIds, discoveredProjects = []) {
    const projectId = discoveredProjects.length > 0 ? discoveredProjects[0].projectId : null;

    // Map of service IDs to test methods
    const serviceMap = {
      // Original APIs
      'youtube': () => this.testYouTubeAPI(),
      'maps-static': () => this.testMapsStaticAPI(),
      'geolocation': () => this.testGeolocationAPI(),
      'custom-search': () => this.testCustomSearchAPI(),
      'fcm': () => this.testFCMAPI(),
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
      // AI/ML APIs
      'vertex-ai': () => this.testVertexAIAPI(),
      'gemini': () => this.testGeminiAPI(),
      'vision': () => this.testVisionAPI(),
      'speech': () => this.testSpeechAPI(),
      'video-intelligence': () => this.testVideoIntelligenceAPI(),
      'natural-language': () => this.testNaturalLanguageAPI(),
      'text-to-speech': () => this.testTextToSpeechAPI(),
      // Infrastructure APIs
      'resource-manager': () => this.testResourceManagerAPI(),
      'compute-engine': () => this.testComputeEngineAPI(projectId),
      'cloud-storage': () => this.testCloudStorageAPI(projectId),
      'secret-manager': () => this.testSecretManagerAPI(projectId),
      'bigquery': () => this.testBigQueryAPI(projectId)
    };

    // If Resource Manager is selected, run it first to discover projects
    let updatedProjects = discoveredProjects;
    let savedResourceManagerResult = null;
    if (selectedServiceIds.includes('resource-manager')) {
      savedResourceManagerResult = await this.testResourceManagerAPI();
      if (savedResourceManagerResult.discoveredProjects && savedResourceManagerResult.discoveredProjects.length > 0) {
        updatedProjects = savedResourceManagerResult.discoveredProjects;
      }
    }

    // Re-create project ID for infrastructure tests if we just discovered new ones
    const updatedProjectId = updatedProjects.length > 0 ? updatedProjects[0].projectId : null;

    // Build test array based on selected service IDs
    const tests = selectedServiceIds
      .filter(id => id !== 'resource-manager') // Already ran if selected
      .map(id => {
        if (!serviceMap[id]) {
          console.warn(`Unknown service ID: ${id}`);
          return null;
        }
        // For infrastructure APIs, use updated project ID
        if (['compute-engine', 'cloud-storage', 'secret-manager', 'bigquery'].includes(id)) {
          // Recreate infrastructure API calls with updated project ID
          if (id === 'compute-engine') return this.testComputeEngineAPI(updatedProjectId);
          if (id === 'cloud-storage') return this.testCloudStorageAPI(updatedProjectId);
          if (id === 'secret-manager') return this.testSecretManagerAPI(updatedProjectId);
          if (id === 'bigquery') return this.testBigQueryAPI(updatedProjectId);
        }
        return serviceMap[id]();
      })
      .filter(test => test !== null);

    const results = await Promise.all(tests);

    // Add Resource Manager result if it was selected (reuse saved result)
    if (savedResourceManagerResult) {
      return [savedResourceManagerResult, ...results];
    }

    return results;
  }
}

// Export for use in extension
if (typeof module !== 'undefined' && module.exports) {
  module.exports = GoogleAPIValidator;
}

