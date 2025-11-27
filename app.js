// app.js - SIMPLE FRONTEND
(function() {
  'use strict';
  
  const API_BASE = '/api';
  
  // Utility functions
  const el = id => document.getElementById(id);
  const showMessage = (message, type = 'info') => {
    alert(`${type.toUpperCase()}: ${message}`);
  };
  
  // Login function
  const login = async (email, password) => {
    try {
      const response = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password })
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error || 'Login failed');
      }
      
      // Store user data
      sessionStorage.setItem('currentUser', JSON.stringify(data));
      showMessage('Login successful!', 'success');
      
      return data;
      
    } catch (error) {
      showMessage(error.message, 'error');
      return null;
    }
  };
  
  // Setup login form
  const setupLoginForm = () => {
    const form = el('formLogin');
    const emailInput = el('loginEmail');
    const passwordInput = el('loginPassword');
    
    if (form && emailInput && passwordInput) {
      // Pre-fill admin credentials for testing
      emailInput.value = 'cyprianmak@gmail.com';
      passwordInput.value = 'Muchandida@1';
      
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const email = emailInput.value.trim();
        const password = passwordInput.value;
        
        if (!email || !password) {
          showMessage('Please enter both email and password', 'error');
          return;
        }
        
        const userData = await login(email, password);
        
        if (userData) {
          // Redirect based on role
          const role = userData.data.user.role;
          if (role === 'admin') {
            window.location.hash = '#control';
          } else if (role === 'shipper') {
            window.location.hash = '#shipper-dashboard';
          } else {
            window.location.hash = '#transporter-dashboard';
          }
        }
      });
    }
  };
  
  // Initialize app
  const init = () => {
    setupLoginForm();
    
    // Show login page by default
    const loginPage = el('page-login');
    if (loginPage) {
      loginPage.classList.remove('hidden');
    }
  };
  
  // Start when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
