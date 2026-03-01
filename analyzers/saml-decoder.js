// Origami SAML Decoder
// Decodes and analyzes SAML Response assertions for security issues

class SAMLDecoder {
  constructor() {
    this.namespaces = {
      saml: 'urn:oasis:names:tc:SAML:2.0:assertion',
      samlp: 'urn:oasis:names:tc:SAML:2.0:protocol',
      ds: 'http://www.w3.org/2000/09/xmldsig#'
    };
  }

  decode(samlResponse) {
    const result = { decoded: null, issues: [] };

    if (!samlResponse || typeof samlResponse !== 'string') {
      result.issues.push({
        severity: 'INFO',
        type: 'saml-empty',
        message: 'SAMLResponse parameter is empty or invalid',
        cwe: null,
        recommendation: 'Ensure the SAMLResponse parameter contains valid base64-encoded XML'
      });
      return result;
    }

    let xml;
    try {
      // URL-decode first if needed
      let decoded = samlResponse;
      if (decoded.includes('%')) {
        try {
          decoded = decodeURIComponent(decoded);
        } catch (e) {
          // Not URL-encoded, continue with original
        }
      }

      // Base64 decode
      xml = atob(decoded);
    } catch (e) {
      // Try with padding fix
      try {
        let padded = samlResponse;
        const pad = padded.length % 4;
        if (pad) padded += '='.repeat(4 - pad);
        xml = atob(padded);
      } catch (e2) {
        result.issues.push({
          severity: 'MEDIUM',
          type: 'saml-decode-error',
          message: 'Failed to base64 decode SAMLResponse: ' + e.message,
          cwe: 'CWE-20',
          recommendation: 'The SAMLResponse may be corrupted or use non-standard encoding'
        });
        return result;
      }
    }

    // Parse the XML
    try {
      const assertion = this.parseAssertion(xml);
      result.decoded = assertion;

      // Run security checks
      this.checkSignature(xml, result.issues);
      this.checkExpiration(assertion, result.issues);
      this.checkAudience(assertion, result.issues);
      this.checkEncryption(xml, result.issues);
      this.checkNameID(assertion, result.issues);
      this.checkConditions(assertion, result.issues);

    } catch (e) {
      console.error('Origami: SAML XML parse error:', e.message);
      result.issues.push({
        severity: 'MEDIUM',
        type: 'saml-parse-error',
        message: 'Failed to parse SAML XML: ' + e.message,
        cwe: 'CWE-20',
        recommendation: 'The SAML assertion XML may be malformed'
      });
    }

    return result;
  }

  parseAssertion(xml) {
    const assertion = {
      issuer: null,
      nameID: null,
      nameIDFormat: null,
      conditions: {
        notBefore: null,
        notOnOrAfter: null,
        audienceRestriction: null
      },
      authnStatement: {
        authnInstant: null,
        sessionIndex: null,
        sessionNotOnOrAfter: null,
        authnContextClassRef: null
      },
      attributes: [],
      hasSigned: false,
      hasEncrypted: false,
      rawXmlLength: xml.length
    };

    // Extract Issuer
    const issuerMatch = xml.match(/<(?:saml:)?Issuer[^>]*>([^<]+)<\/(?:saml:)?Issuer>/);
    if (issuerMatch) {
      assertion.issuer = issuerMatch[1].trim();
    }

    // Extract NameID
    const nameIDMatch = xml.match(/<(?:saml:)?NameID([^>]*)>([^<]+)<\/(?:saml:)?NameID>/);
    if (nameIDMatch) {
      assertion.nameID = nameIDMatch[2].trim();
      const formatMatch = nameIDMatch[1].match(/Format="([^"]+)"/);
      if (formatMatch) {
        assertion.nameIDFormat = formatMatch[1];
      }
    }

    // Extract Conditions
    const conditionsMatch = xml.match(/<(?:saml:)?Conditions([^>]*)>/);
    if (conditionsMatch) {
      const attrs = conditionsMatch[1];
      const notBeforeMatch = attrs.match(/NotBefore="([^"]+)"/);
      const notOnOrAfterMatch = attrs.match(/NotOnOrAfter="([^"]+)"/);

      if (notBeforeMatch) assertion.conditions.notBefore = notBeforeMatch[1];
      if (notOnOrAfterMatch) assertion.conditions.notOnOrAfter = notOnOrAfterMatch[1];
    }

    // Extract AudienceRestriction
    const audienceMatch = xml.match(/<(?:saml:)?Audience[^>]*>([^<]+)<\/(?:saml:)?Audience>/);
    if (audienceMatch) {
      assertion.conditions.audienceRestriction = audienceMatch[1].trim();
    }

    // Extract AuthnStatement
    const authnMatch = xml.match(/<(?:saml:)?AuthnStatement([^>]*)>/);
    if (authnMatch) {
      const attrs = authnMatch[1];
      const instantMatch = attrs.match(/AuthnInstant="([^"]+)"/);
      const sessionIndexMatch = attrs.match(/SessionIndex="([^"]+)"/);
      const sessionNotOnOrAfterMatch = attrs.match(/SessionNotOnOrAfter="([^"]+)"/);

      if (instantMatch) assertion.authnStatement.authnInstant = instantMatch[1];
      if (sessionIndexMatch) assertion.authnStatement.sessionIndex = sessionIndexMatch[1];
      if (sessionNotOnOrAfterMatch) assertion.authnStatement.sessionNotOnOrAfter = sessionNotOnOrAfterMatch[1];
    }

    // Extract AuthnContextClassRef
    const authnContextMatch = xml.match(/<(?:saml:)?AuthnContextClassRef[^>]*>([^<]+)<\/(?:saml:)?AuthnContextClassRef>/);
    if (authnContextMatch) {
      assertion.authnStatement.authnContextClassRef = authnContextMatch[1].trim();
    }

    // Extract Attributes
    const attrPattern = /<(?:saml:)?Attribute\s+Name="([^"]+)"[^>]*>[\s\S]*?<(?:saml:)?AttributeValue[^>]*>([^<]*)<\/(?:saml:)?AttributeValue>[\s\S]*?<\/(?:saml:)?Attribute>/g;
    let attrMatch;
    while ((attrMatch = attrPattern.exec(xml)) !== null) {
      assertion.attributes.push({
        name: attrMatch[1],
        value: attrMatch[2].trim()
      });
    }

    // Check for Signature
    assertion.hasSigned = xml.includes('Signature') || xml.includes('ds:Signature');

    // Check for EncryptedAssertion
    assertion.hasEncrypted = xml.includes('EncryptedAssertion') || xml.includes('EncryptedID');

    return assertion;
  }

  checkSignature(xml, issues) {
    const hasSignature = xml.includes('<ds:Signature') || xml.includes('<Signature');
    const hasSignatureValue = xml.includes('<ds:SignatureValue') || xml.includes('<SignatureValue');

    if (!hasSignature || !hasSignatureValue) {
      issues.push({
        severity: 'CRITICAL',
        type: 'saml-missing-signature',
        message: 'SAML assertion does not contain a digital signature - assertions can be forged by an attacker',
        cwe: 'CWE-347',
        recommendation: 'Require all SAML assertions to be digitally signed. Validate the signature against the trusted IdP certificate before processing.'
      });
    }

    // Check for SignedInfo reference
    if (hasSignature && !xml.includes('Reference')) {
      issues.push({
        severity: 'HIGH',
        type: 'saml-incomplete-signature',
        message: 'SAML signature found but may be incomplete - missing Reference element',
        cwe: 'CWE-347',
        recommendation: 'Ensure the signature covers the entire assertion with proper Reference and DigestValue elements'
      });
    }

    // Check for potential XML Signature Wrapping (XSW) indicators
    const assertionCount = (xml.match(/<(?:saml:)?Assertion/g) || []).length;
    if (assertionCount > 1) {
      issues.push({
        severity: 'HIGH',
        type: 'saml-multiple-assertions',
        message: 'Multiple SAML Assertion elements detected (' + assertionCount + ') - potential XML Signature Wrapping (XSW) attack',
        cwe: 'CWE-347',
        recommendation: 'Validate that only one assertion exists and that the signed assertion is the one being processed'
      });
    }
  }

  checkExpiration(assertion, issues) {
    const now = new Date();

    if (assertion.conditions.notOnOrAfter) {
      const expiry = new Date(assertion.conditions.notOnOrAfter);
      if (!isNaN(expiry.getTime()) && expiry < now) {
        issues.push({
          severity: 'MEDIUM',
          type: 'saml-assertion-expired',
          message: 'SAML assertion has expired (NotOnOrAfter: ' + assertion.conditions.notOnOrAfter + ')',
          cwe: 'CWE-613',
          recommendation: 'Reject expired SAML assertions. Ensure time synchronization between SP and IdP (NTP).'
        });
      }
    } else {
      issues.push({
        severity: 'MEDIUM',
        type: 'saml-no-expiration',
        message: 'SAML assertion has no NotOnOrAfter condition - assertion never expires',
        cwe: 'CWE-613',
        recommendation: 'SAML assertions should include NotOnOrAfter conditions to limit their validity window'
      });
    }

    if (assertion.conditions.notBefore) {
      const notBefore = new Date(assertion.conditions.notBefore);
      if (!isNaN(notBefore.getTime()) && notBefore > now) {
        issues.push({
          severity: 'LOW',
          type: 'saml-not-yet-valid',
          message: 'SAML assertion is not yet valid (NotBefore: ' + assertion.conditions.notBefore + ')',
          cwe: 'CWE-613',
          recommendation: 'This may indicate clock skew between the IdP and SP. Check NTP synchronization.'
        });
      }
    }

    // Check session expiration
    if (assertion.authnStatement.sessionNotOnOrAfter) {
      const sessionExpiry = new Date(assertion.authnStatement.sessionNotOnOrAfter);
      if (!isNaN(sessionExpiry.getTime()) && sessionExpiry < now) {
        issues.push({
          severity: 'LOW',
          type: 'saml-session-expired',
          message: 'SAML session has expired (SessionNotOnOrAfter: ' + assertion.authnStatement.sessionNotOnOrAfter + ')',
          cwe: 'CWE-613',
          recommendation: 'Enforce session expiration and require re-authentication'
        });
      }
    }
  }

  checkAudience(assertion, issues) {
    if (!assertion.conditions.audienceRestriction) {
      issues.push({
        severity: 'MEDIUM',
        type: 'saml-no-audience',
        message: 'SAML assertion has no AudienceRestriction - assertion could be replayed to other service providers',
        cwe: 'CWE-287',
        recommendation: 'Include AudienceRestriction in SAML assertions and validate the audience matches your SP entity ID'
      });
      return;
    }

    // Check if audience matches current origin
    const currentOrigin = window.location.origin;
    const audience = assertion.conditions.audienceRestriction;

    if (!audience.includes(currentOrigin) && !currentOrigin.includes(audience)) {
      issues.push({
        severity: 'HIGH',
        type: 'saml-audience-mismatch',
        message: 'SAML audience restriction ("' + audience.substring(0, 80) + '") does not match current origin ("' + currentOrigin + '")',
        cwe: 'CWE-287',
        recommendation: 'The SAML assertion may be intended for a different service provider. Reject assertions with mismatched audience.'
      });
    }
  }

  checkEncryption(xml, issues) {
    const hasEncrypted = xml.includes('EncryptedAssertion') || xml.includes('EncryptedID');

    if (!hasEncrypted && xml.includes('NameID')) {
      // Check if sensitive data is in plain text
      const nameIDMatch = xml.match(/<(?:saml:)?NameID[^>]*>([^<]+)<\/(?:saml:)?NameID>/);
      if (nameIDMatch) {
        const nameID = nameIDMatch[1];
        // Check if it looks like an email or sensitive identifier
        if (nameID.includes('@') || /^\d{3}-\d{2}-\d{4}$/.test(nameID)) {
          issues.push({
            severity: 'LOW',
            type: 'saml-unencrypted-nameid',
            message: 'SAML NameID contains potentially sensitive data in unencrypted form',
            cwe: 'CWE-319',
            recommendation: 'Consider using EncryptedID to protect sensitive identifiers in SAML assertions'
          });
        }
      }
    }
  }

  checkNameID(assertion, issues) {
    if (!assertion.nameID) {
      issues.push({
        severity: 'LOW',
        type: 'saml-no-nameid',
        message: 'SAML assertion does not contain a NameID element',
        cwe: null,
        recommendation: 'NameID is typically required to identify the authenticated subject'
      });
    }

    // Check NameID format
    if (assertion.nameIDFormat) {
      const transientFormat = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient';
      if (assertion.nameIDFormat === transientFormat) {
        // Transient is fine for privacy but worth noting
        // No issue raised - this is a valid privacy-preserving format
      }
    }
  }

  checkConditions(assertion, issues) {
    if (!assertion.conditions.notBefore && !assertion.conditions.notOnOrAfter) {
      issues.push({
        severity: 'MEDIUM',
        type: 'saml-no-time-conditions',
        message: 'SAML assertion has no time-based conditions (NotBefore/NotOnOrAfter) - assertion has unlimited validity',
        cwe: 'CWE-613',
        recommendation: 'Always include time-based conditions to limit the validity window of SAML assertions'
      });
    }

    // Check for excessively long validity window
    if (assertion.conditions.notBefore && assertion.conditions.notOnOrAfter) {
      const start = new Date(assertion.conditions.notBefore);
      const end = new Date(assertion.conditions.notOnOrAfter);
      if (!isNaN(start.getTime()) && !isNaN(end.getTime())) {
        const durationMs = end - start;
        const durationMinutes = durationMs / 60000;

        if (durationMinutes > 30) {
          issues.push({
            severity: 'LOW',
            type: 'saml-long-validity',
            message: 'SAML assertion has a long validity window (' + Math.round(durationMinutes) + ' minutes). Recommended maximum is 5-10 minutes.',
            cwe: 'CWE-613',
            recommendation: 'Reduce the assertion validity window to 5-10 minutes to limit replay attack opportunities'
          });
        }
      }
    }
  }
}

window.SAMLDecoder = SAMLDecoder;
