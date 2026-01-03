const tokenResponse = await axios.post(
  'https://auth.fanvue.com/oauth2/token',  // ← This is the correct endpoint per Fanvue docs
  new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri,
    code_verifier: session.codeVerifier,
  }),
  {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${basicAuth}`,
      'Accept': 'application/json',
      'User-Agent': 'Fanvue-API-Client/1.0'
    },
    timeout: 30000
  }
);
