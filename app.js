// app.js - SIMPLE FRONTEND
(function() {
  'use strict';
  
  const API_BASE = '/api';
  
  // Utility functions
  const el = id => document.getElementById(id);
  const setHidden = (id, hid) => { const e = el(id); if(e) e.classList[hid ? 'add' : 'remove']('hidden'); };
  
  // Notification system
  function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    
    const container = document.getElementById('notificationContainer');
    if (!container) return;
    
    container.appendChild(notification);
    
    setTimeout(() => {
      notification.classList.add('show');
    }, 100);
    
    setTimeout(() => {
      notification.classList.remove('show');
      setTimeout(() => {
        if (notification.parentNode) {
          notification.remove();
        }
      }, 300);
    }, 5000);
  }
  
  // API helper
  const apiRequest = async (endpoint, options = {}) => {
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers
    };
    
    try {
      const response = await fetch(`${API_BASE}${endpoint}`, {
        ...options,
        headers
      });
      
      if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new Error(error.error || `API error: ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      throw error;
    }
  };
  
  // Login function
  const login = async (email, password) => {
    try {
      const user = await apiRequest('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password })
      });
      if (user) {
        sessionStorage.setItem('currentUser', JSON.stringify(user));
        showNotification('Login successful', 'success');
        return user;
      }
      return null;
    } catch (error) {
      showNotification('Login failed: ' + error.message, 'error');
      return null;
    }
  };
  
  const logout = () => {
    sessionStorage.removeItem('currentUser');
    showNotification('Logged out successfully', 'info');
    location.hash = '#login';
    render();
  };
  
  // Render header
  const renderHeader = async () => {
    const u = JSON.parse(sessionStorage.getItem('currentUser') || 'null');
    const navLinks = el('navLinks');
    const authUser = el('authUser');
    const btnLoginNav = el('btnLoginNav');
    const btnLogout = el('btnLogout');
    
    if (u && u.data && u.data.user) {
      if (navLinks) navLinks.innerHTML = '';
      if (authUser) authUser.textContent = u.data.user.name;
      if (btnLoginNav) btnLoginNav.classList.add('hidden');
      if (btnLogout) btnLogout.classList.remove('hidden');
      
      if (navLinks) {
        const links = [];
        
        if (u.data.user.role === 'shipper') {
          links.push(
            { href: '#shipper-dashboard', text: 'Dashboard' },
            { href: '#shipper-post', text: 'Post Load' },
            { href: '#market', text: 'Market' },
            { href: '#messages', text: 'Messages' },
            { href: '#shipper-profile', text: 'Profile' }
          );
        } else if (u.data.user.role === 'transporter') {
          links.push(
            { href: '#transporter-dashboard', text: 'Dashboard' },
            { href: '#shipper-post', text: 'Post Load' },
            { href: '#market', text: 'Market' },
            { href: '#messages', text: 'Messages' },
            { href: '#transporter-profile', text: 'Profile' }
          );
        } else if (u.data.user.role === 'admin') {
          links.push(
            { href: '#control', text: 'Admin' },
            { href: '#shipper-dashboard', text: 'Shipper Dashboard' },
            { href: '#transporter-dashboard', text: 'Transporter Dashboard' },
            { href: '#market', text: 'Market' },
            { href: '#messages', text: 'Messages' }
          );
        }
        
        links.forEach(link => {
          const a = document.createElement('a');
          a.className = 'btn';
          a.href = link.href;
          a.textContent = link.text;
          navLinks.appendChild(a);
        });
      }
    } else {
      if (navLinks) navLinks.innerHTML = '';
      if (authUser) authUser.textContent = '';
      if (btnLoginNav) btnLoginNav.classList.remove('hidden');
      if (btnLogout) btnLogout.classList.add('hidden');
    }
  };
  
  // Main render function
  const render = async () => {
    await renderHeader();
    
    // Hide all pages first
    document.querySelectorAll('section').forEach(s => s.classList.add('hidden'));
    
    const hash = location.hash.slice(1) || 'index';
    const u = JSON.parse(sessionStorage.getItem('currentUser') || 'null');
    
    // Check access
    let canAccess = false;
    if (hash === 'index' || hash === 'login' || hash === 'register-options' || 
        hash === 'register-shipper' || hash === 'register-transporter') {
      canAccess = true;
    } else if (u) {
      canAccess = true;
    }
    
    if (!canAccess) {
      location.hash = '#login';
      return;
    }
    
    // Show the appropriate page
    setHidden(`page-${hash}`, false);
  };
  
  // Event handlers
  const init = () => {
    // Login form
    const loginForm = el('formLogin');
    if (loginForm) {
      loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = el('loginEmail')?.value;
        const password = el('loginPassword')?.value;
        if (!email || !password) {
          showNotification('Please fill in all fields', 'error');
          return;
        }
        
        try {
          const user = await login(email, password);
          if (user) {
            location.hash = user.data.user.role === 'admin' ? '#control' : 
                           user.data.user.role === 'shipper' ? '#shipper-dashboard' : '#transporter-dashboard';
          }
        } catch (error) {
          console.error('Login error:', error);
        }
      });
    }
    
    // Logout
    const logoutBtn = el('btnLogout');
    if (logoutBtn) logoutBtn.addEventListener('click', logout);
    
    // Initialize the app
    render();
    window.addEventListener('hashchange', render);
  };
  
  // Start the application
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
