const validateAuthServiceToken = async (req, res, next) => {
  try {
    const token = req.cookies.accessToken;
    
    if (!token) {
      return res.status(401).json({ error: "No token provided" });
    }
    
    // Validate token with auth service
    const response = await fetch("http://auth-service.com/auth/validate-token", {
      method: "POST",
      headers: { 
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`
      }
    });
    
    if (!response.ok) {
      return res.status(401).json({ error: "Invalid token" });
    }
    
    const userData = await response.json();
    req.user = userData.user;
    next();
  } catch (error) {
    console.error("Token validation error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
};