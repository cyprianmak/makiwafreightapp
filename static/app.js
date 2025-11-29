// app.js - MakiwaFreight Production Frontend with Access Control
(function() {
  'use strict';
  
  // Configuration
  const API_BASE = '/api';
  const LOAD_EXPIRY_DAYS = 7;
  const SESSION_TIMEOUT_MINUTES = 30;
  const SESSION_WARNING_MINUTES = 5;
  
  // Page definitions for access control
  const PAGES = {
    'shipper-dashboard': { name: 'Shipper Dashboard', roles: ['shipper', 'admin'] },
    'shipper-post': { name: 'Post Load', roles: ['admin', 'shipper', 'transporter'] },
    'shipper-profile': { name: 'Shipper Profile', roles: ['shipper', 'admin'] },
    'transporter-dashboard': { name: 'Transporter Dashboard', roles: ['transporter', 'admin'] },
    'transporter-profile': { name: 'Transporter Profile', roles: ['transporter', 'admin'] },
    'market': { name: 'Market', roles: ['shipper', 'transporter', 'admin'] },
    'messages': { name: 'Messages', roles: ['shipper', 'transporter', 'admin'] },
    'control': { name: 'Admin Control', roles: ['admin'] }
  };
  
  // Session timeout variables
  let sessionTimeout;
  let sessionWarningTimeout;
  let lastActivityTime = Date.now();
  
  // Global flag to force refresh permissions
  let forceRefreshPermissions = false;
  
  // Utility functions
  const now = () => new Date().toISOString();
  const el = id => document.getElementById(id);
  const setText = (id, txt) => { const e = el(id); if(e) e.textContent = txt; };
  const setHidden = (id, hid) => { const e = el(id); if(e) e.classList[hid ? 'add' : 'remove']('hidden'); };
  
  // Sanitize input to prevent XSS
  const sanitize = str => {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str.toString();
    return div.innerHTML;
  };
  
  // Validate email format
  const isValidEmail = email => {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
  };

  // SUPER ADMIN EMAIL - cprianmak@gmail.com has all powers
  const SUPER_ADMIN_EMAIL = 'cprianmak@gmail.com';

  // Check if user is admin or super admin
  const isAdmin = user => {
    if (!user) return false;
    return user.role === 'admin' || user.email === SUPER_ADMIN_EMAIL;
  };

  // Check if user is super admin
  const isSuperAdmin = user => {
    return user && user.email === SUPER_ADMIN_EMAIL;
  };

  // Error handling wrapper
  const handleError = async (fn, fallbackMsg = 'An error occurred') => {
    try {
      return await fn();
    } catch (error) {
      console.error('MakiwaFreight Error:', error);
      showNotification(fallbackMsg + ': ' + error.message, 'error');
      return null;
    }
  };
  
  // Show loading state on a button
  const setButtonLoading = (button, isLoading) => {
    if (!button) return;
    
    if (isLoading) {
      button.classList.add('loading');
      button.disabled = true;
      
      if (!button.querySelector('.loading')) {
        const spinner = document.createElement('span');
        spinner.className = 'loading';
        button.appendChild(spinner);
      }
    } else {
      button.classList.remove('loading');
      button.disabled = false;
      
      const spinner = button.querySelector('.loading');
      if (spinner) {
        spinner.remove();
      }
    }
  };
  
  // Notification system
  function showNotification(message, type = 'info') {
    const container = el('notificationContainer');
    if (!container) return;
    
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    
    container.appendChild(notification);
    
    // Trigger animation
    setTimeout(() => {
      notification.classList.add('show');
    }, 10);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
      notification.classList.remove('show');
      setTimeout(() => {
        if (notification.parentNode) {
          notification.remove();
        }
      }, 300);
    }, 5000);
  }
  
  // Session timeout management
  const resetSessionTimer = () => {
    lastActivityTime = Date.now();
    clearTimeout(sessionTimeout);
    clearTimeout(sessionWarningTimeout);
    
    sessionWarningTimeout = setTimeout(showSessionWarning, (SESSION_TIMEOUT_MINUTES - SESSION_WARNING_MINUTES) * 60 * 1000);
    sessionTimeout = setTimeout(logoutDueToInactivity, SESSION_TIMEOUT_MINUTES * 60 * 1000);
  };
  
  const showSessionWarning = () => {
    const modal = el('sessionTimeoutModal');
    const timer = el('sessionTimer');
    
    if (!modal || !timer) return;
    
    let timeLeft = SESSION_WARNING_MINUTES * 60;
    
    const updateTimer = () => {
      const minutes = Math.floor(timeLeft / 60);
      const seconds = timeLeft % 60;
      timer.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
      
      if (timeLeft > 0) {
        timeLeft--;
        setTimeout(updateTimer, 1000);
      }
    };
    
    updateTimer();
    modal.classList.remove('hidden');
  };
  
  const logoutDueToInactivity = () => {
    showNotification('Your session has expired due to inactivity', 'warning');
    logout();
  };
  
  const extendSession = () => {
    const modal = el('sessionTimeoutModal');
    if (modal) {
      modal.classList.add('hidden');
    }
    resetSessionTimer();
    showNotification('Session extended', 'success');
  };
  
  // Set up session timeout event listeners
  const setupSessionTimeout = () => {
    const activityEvents = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'];
    activityEvents.forEach(event => {
      document.addEventListener(event, resetSessionTimer, false);
    });
    
    el('extendSession')?.addEventListener('click', extendSession);
    el('logoutSession')?.addEventListener('click', logout);
    
    resetSessionTimer();
  };
  
  // Show rate limit warning
  const showRateLimitWarning = () => {
    showNotification('Too many requests. Please slow down.', 'warning');
  };
  
  // API helper functions
  const apiRequest = async (endpoint, options = {}) => {
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers
    };
    
    // FIX: Get user data directly from sessionStorage to avoid sync issues
    let user = null;
    let token = null;
    
    try {
      const userData = sessionStorage.getItem('currentUser');
      if (userData) {
        user = JSON.parse(userData);
        token = user.token;
      }
      
      // Also check authToken separately
      if (!token) {
        token = sessionStorage.getItem('authToken');
      }
    } catch (e) {
      console.error('Error reading session storage:', e);
    }
    
    // FIX: Use whatever token we found
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    } else {
      console.warn('❌ No token found for API request');
    }
    
    try {
      const response = await fetch(`${API_BASE}${endpoint}`, {
        ...options,
        headers
      });
      
      if (response.status === 401) {
        // Clear all session data
        sessionStorage.removeItem('currentUser');
        sessionStorage.removeItem('authToken');
        showNotification('Please login again', 'error');
        location.hash = '#login';
        throw new Error('Please login to continue');
      }
      
      if (response.status === 429) {
        showRateLimitWarning();
        throw new Error('Rate limit exceeded. Please try again later.');
      }
      
      const data = await response.json().catch(() => ({}));
      
      if (!response.ok) {
        throw new Error(data.error || data.message || `API error: ${response.status}`);
      }
      
      return data;
    } catch (error) {
      console.error('API request failed:', error);
      if (error instanceof TypeError && error.message.includes('fetch')) {
        throw new Error('Network error. Please check your connection and try again.');
      }
      throw error;
    }
  };
  
  // Get current user synchronously - FIXED VERSION
  const getCurrentUserSync = () => {
    try {
      const userData = sessionStorage.getItem('currentUser');
      const authToken = sessionStorage.getItem('authToken');
      
      if (userData) {
        const user = JSON.parse(userData);
        // Merge the token into user object
        if (authToken) {
          user.token = authToken;
        }
        // Auto-promote cprianmak@gmail.com to admin if not already
        if (user.email === SUPER_ADMIN_EMAIL && user.role !== 'admin') {
          user.role = 'admin';
          sessionStorage.setItem('currentUser', JSON.stringify(user));
        }
        return user;
      }
      return null;
    } catch (error) {
      console.error('Error getting current user:', error);
      return null;
    }
  };

  // Get user access permissions - SIMPLIFIED VERSION
  const getUserAccessPermissions = async () => {
    const user = getCurrentUserSync();
    if (!user) return null;
    
    // Admins and super admins have full access - no need to check
    if (isAdmin(user)) {
      return {
        market: { enabled: true },
        'post-load': { enabled: true },
        messages: { enabled: true }
      };
    }
    
    try {
      // For regular users, ALWAYS fetch fresh access permissions
      console.log('🔄 Fetching fresh access permissions for user:', user.email);
      const response = await apiRequest(`/admin/users/${user.id}/access`);
      
      if (response.success) {
        const permissions = response.data.pages || {
          market: { enabled: false },
          'post-load': { enabled: false },
          messages: { enabled: false }
        };
        
        console.log('✅ Loaded access permissions:', permissions, 'for user:', user.email);
        return permissions;
      } else {
        throw new Error('Failed to fetch access permissions');
      }
    } catch (error) {
      console.error('❌ Error fetching user access permissions:', error);
      // Return default restricted access on error
      return {
        market: { enabled: false },
        'post-load': { enabled: false },
        messages: { enabled: false }
      };
    }
  };

  // Force refresh permissions for next check
  const forceRefreshPermissionsNextTime = () => {
    forceRefreshPermissions = true;
    console.log('🚨 Force refresh permissions flag set');
  };

  // Check if user has access to specific feature
  const hasAccessTo = async (feature) => {
    const user = getCurrentUserSync();
    if (!user) return false;
    
    // Admins and super admins have full access
    if (isAdmin(user)) return true;
    
    const permissions = await getUserAccessPermissions();
    if (!permissions) return false;
    
    const hasAccess = permissions[feature]?.enabled === true;
    console.log(`🔐 Access check for ${feature}:`, hasAccess, 'User:', user.email);
    return hasAccess;
  };

  // Check page access with both role-based and permission-based checks
  const canAccessPage = async (user, pageId) => {
    if (!user) return false;
    
    // Admins and super admins can access all pages
    if (isAdmin(user)) return true;
    
    // Check role-based access first
    const page = PAGES[pageId];
    if (!page || !page.roles.includes(user.role)) {
      console.log(`❌ Role-based access denied for ${pageId} - user role: ${user.role}`);
      return false;
    }
    
    // For specific pages, check additional permissions
    if (pageId === 'market') {
      return await hasAccessTo('market');
    }
    
    if (pageId === 'shipper-post') {
      return await hasAccessTo('post-load');
    }
    
    if (pageId === 'messages') {
      return await hasAccessTo('messages');
    }
    
    // Dashboard and profile pages are always accessible once logged in
    if (pageId === 'shipper-dashboard' || pageId === 'transporter-dashboard' || 
        pageId === 'shipper-profile' || pageId === 'transporter-profile') {
      return true;
    }
    
    return false;
  };
  
  // Authentication API functions
  const login = async (email, password) => {
    const response = await apiRequest('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password })
    });
    
    if (response.success) {
        let userData = response.data;
        
        // Auto-promote cprianmak@gmail.com to admin
        if (userData.user.email === SUPER_ADMIN_EMAIL) {
          userData.user.role = 'admin';
          showNotification('Welcome Super Admin!', 'success');
        }
        
        // FIX: Ensure token is included in user object
        const userWithToken = {
          ...userData.user,
          token: userData.token
        };
        
        sessionStorage.setItem('currentUser', JSON.stringify(userWithToken));
        sessionStorage.setItem('authToken', userData.token);
        
        showNotification('Login successful', 'success');
        setupSessionTimeout();
        return userWithToken;
    } else {
        throw new Error(response.error || response.message);
    }
  };
  
  const logout = () => {
    clearTimeout(sessionTimeout);
    clearTimeout(sessionWarningTimeout);
    
    sessionStorage.removeItem('currentUser');
    sessionStorage.removeItem('authToken');
    
    showNotification('Logged out successfully', 'info');
    location.hash = '#login';
    render();
  };
  
  // User API functions
  const registerUser = async (data) => {
    // Auto-assign admin role for super admin email
    if (data.email === SUPER_ADMIN_EMAIL) {
      data.role = 'admin';
    }
    
    const response = await apiRequest('/auth/register', {
      method: 'POST',
      body: JSON.stringify(data)
    });
    
    if (response.success) {
      let userData = response.data.user;
      userData.token = response.data.token;
      
      // Ensure super admin has admin role
      if (userData.email === SUPER_ADMIN_EMAIL) {
        userData.role = 'admin';
      }
      
      sessionStorage.setItem('currentUser', JSON.stringify(userData));
      sessionStorage.setItem('authToken', userData.token);
      
      if (userData.email === SUPER_ADMIN_EMAIL) {
        showNotification(`Super Admin Registration successful! Welcome ${data.name}`, 'success');
      } else {
        showNotification(`Registration successful! Welcome ${data.name}`, 'success');
      }
      
      setupSessionTimeout();
      
      // Show membership number
      if (data.role === 'shipper' || (data.email === SUPER_ADMIN_EMAIL && data.role === 'admin')) {
        const shipperMembershipEl = el('shipperMembershipNumber');
        if (shipperMembershipEl) {
          shipperMembershipEl.textContent = `Your Membership Number: ${userData.membership_number}`;
          shipperMembershipEl.classList.remove('hidden');
        }
      } else if (data.role === 'transporter') {
        const transporterMembershipEl = el('transporterMembershipNumber');
        if (transporterMembershipEl) {
          transporterMembershipEl.textContent = `Your Membership Number: ${userData.membership_number}`;
          transporterMembershipEl.classList.remove('hidden');
        }
      }

      return userData;
    } else {
      throw new Error(response.error || response.message);
    }
  };
  
  const updateUserProfile = async (profileData) => {
    const response = await apiRequest('/users/me', {
      method: 'PUT',
      body: JSON.stringify(profileData)
    });
    
    if (response.success) {
      const updatedUser = response.data.user;
      const currentUser = getCurrentUserSync();
      const mergedUser = { ...currentUser, ...updatedUser };
      
      // Ensure super admin retains admin role
      if (mergedUser.email === SUPER_ADMIN_EMAIL) {
        mergedUser.role = 'admin';
      }
      
      sessionStorage.setItem('currentUser', JSON.stringify(mergedUser));
      
      showNotification('Profile updated successfully', 'success');
      return mergedUser;
    } else {
      throw new Error(response.error || response.message);
    }
  };
  
  // Load API functions
  const postLoad = async (payload) => {
    // Check access before posting
    const hasAccess = await hasAccessTo('post-load');
    if (!hasAccess) {
      showNotification('You do not have permission to post loads. Please contact administrator.', 'error');
      throw new Error('Access denied');
    }
    
    const response = await apiRequest('/loads', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    
    if (response.success) {
      showNotification('Load posted successfully', 'success');
      return response.data.load;
    } else {
      throw new Error(response.error || response.message);
    }
  };
  
  const getLoads = async (filters = {}) => {
    // Check access before fetching loads
    const hasAccess = await hasAccessTo('market');
    if (!hasAccess) {
      showNotification('You do not have permission to access the market.', 'error');
      throw new Error('Access denied');
    }
    
    const response = await apiRequest('/loads');
    
    if (response.success) {
        return response.data.loads;
    } else {
        throw new Error(response.error || response.message);
    }
  };
  
  const getMyLoads = async () => {
    const response = await apiRequest('/my-loads');
    
    if (response.success) {
        return response.data.loads;
    } else {
        throw new Error(response.error || response.message);
    }
  };

  const deleteLoad = async (loadId) => {
    const response = await apiRequest(`/loads/${loadId}`, {
      method: 'DELETE'
    });
    
    if (response.success) {
      showNotification('Load deleted successfully', 'success');
      return response.data;
    } else {
      throw new Error(response.error || response.message);
    }
  };
  
  // Message API functions
  const sendMessage = async (toMembership, body) => {
    // Check access before sending message
    const hasAccess = await hasAccessTo('messages');
    if (!hasAccess) {
      showNotification('You do not have permission to send messages. Please contact administrator.', 'error');
      throw new Error('Access denied');
    }
    
    const response = await apiRequest('/messages', {
        method: 'POST',
        body: JSON.stringify({
            recipient_membership: toMembership,
            body: body
        })
    });
    
    if (response.success) {
        showNotification('Message sent successfully', 'success');
        return response.data;
    } else {
        throw new Error(response.error || response.message);
    }
  };

  const getMessages = async () => {
    // Check access before fetching messages
    const hasAccess = await hasAccessTo('messages');
    if (!hasAccess) {
      showNotification('You do not have permission to access messages.', 'error');
      throw new Error('Access denied');
    }
    
    const response = await apiRequest('/messages');
    
    if (response.success) {
        return response.data.messages;
    } else {
        throw new Error(response.error || response.message);
    }
  };

  // Update UI based on access permissions
  const updateUIBasedOnAccess = async () => {
    const user = getCurrentUserSync();
    if (!user || isAdmin(user)) return;
    
    const permissions = await getUserAccessPermissions();
    
    console.log('🔄 Updating UI with permissions:', permissions, 'for user:', user.email);
    
    // Update dashboard content visibility
    const hasAnyAccess = permissions.market.enabled || permissions['post-load'].enabled || permissions.messages.enabled;
    
    if (user.role === 'shipper') {
      setHidden('shipperDashboardContent', !hasAnyAccess);
      setHidden('shipperAccessRestricted', hasAnyAccess);
      
      // Update access warning banner
      const accessWarning = el('accessWarningShipper');
      if (accessWarning) {
        if (hasAnyAccess) {
          accessWarning.classList.add('hidden');
        } else {
          accessWarning.classList.remove('hidden');
          accessWarning.textContent = 'Your account has restricted access. Please contact administrator for full platform features.';
        }
      }
    } else if (user.role === 'transporter') {
      setHidden('transporterDashboardContent', !hasAnyAccess);
      setHidden('transporterAccessRestricted', hasAnyAccess);
      
      // Update access warning banner
      const accessWarning = el('accessWarningTransporter');
      if (accessWarning) {
        if (hasAnyAccess) {
          accessWarning.classList.add('hidden');
        } else {
          accessWarning.classList.remove('hidden');
          accessWarning.textContent = 'Your account has restricted access. Please contact administrator for full platform features.';
        }
      }
    }
    
    // Update form visibility based on specific permissions
    setHidden('formPostLoad', !permissions['post-load'].enabled);
    setHidden('postLoadAccessRestricted', permissions['post-load'].enabled);
    
    setHidden('marketContent', !permissions.market.enabled);
    setHidden('marketAccessRestricted', permissions.market.enabled);
    
    setHidden('messagesContent', !permissions.messages.enabled);
    setHidden('messagesAccessRestricted', permissions.messages.enabled);
    
    // Update navigation based on permissions
    await updateNavigation();
  };

  // Update navigation based on permissions
  const updateNavigation = async () => {
    const user = getCurrentUserSync();
    if (!user) return;
    
    // Force re-render header to update navigation links
    await renderHeader();
  };

  // Render functions
  const renderShipperDashboard = async () => {
    const user = getCurrentUserSync();
    if (!user || (user.role !== 'shipper' && !isAdmin(user))) return;
    
    try {
        const tbody = el('tableMyLoadsShipper')?.querySelector('tbody');
        if (!tbody) return;
        
        // Clear table
        tbody.innerHTML = '';
        
        const loads = await getMyLoads();
        
        if (loads.length === 0) {
            const row = document.createElement('tr');
            const cell = document.createElement('td');
            cell.colSpan = 9;
            cell.className = 'muted';
            cell.textContent = 'No loads posted yet.';
            row.appendChild(cell);
            tbody.appendChild(row);
            return;
        }
        
        loads.forEach(load => {
            const row = document.createElement('tr');
            const isExpired = new Date(load.expires_at) < new Date();
            
            row.innerHTML = `
                <td>${sanitize(load.ref)}</td>
                <td>${sanitize(load.origin)}</td>
                <td>${sanitize(load.destination)}</td>
                <td>${sanitize(load.date)}</td>
                <td>${new Date(load.expires_at).toLocaleDateString()}</td>
                <td>${sanitize(load.cargo_type)}</td>
                <td>${load.weight} tons</td>
                <td><span class="status-badge ${isExpired ? 'status-expired' : 'status-available'}">${isExpired ? 'Expired' : 'Active'}</span></td>
                <td>
                    <button class="btn small" onclick="editUserLoad('${load.id}')">Edit</button>
                    <button class="btn small danger" onclick="deleteUserLoad('${load.id}')">Delete</button>
                </td>
            `;
            tbody.appendChild(row);
        });
        
        // Update UI based on access permissions
        await updateUIBasedOnAccess();
        
    } catch (error) {
        console.error('Error rendering shipper dashboard:', error);
        showNotification('Failed to load your loads', 'error');
    }
  };

  const renderTransporterDashboard = async () => {
    const user = getCurrentUserSync();
    if (!user || (user.role !== 'transporter' && !isAdmin(user))) return;
    
    try {
      const tbody = el('tableMyLoadsTransporter')?.querySelector('tbody');
      if (!tbody) return;
      
      // Clear table
      tbody.innerHTML = '';
      
      const loads = await getMyLoads();
      
      if (loads.length === 0) {
          const row = document.createElement('tr');
          const cell = document.createElement('td');
          cell.colSpan = 9;
          cell.className = 'muted';
          cell.textContent = 'No loads posted yet.';
          row.appendChild(cell);
          tbody.appendChild(row);
          return;
      }
      
      loads.forEach(load => {
          const row = document.createElement('tr');
          const isExpired = new Date(load.expires_at) < new Date();
          
          row.innerHTML = `
              <td>${sanitize(load.ref)}</td>
              <td>${sanitize(load.origin)}</td>
              <td>${sanitize(load.destination)}</td>
              <td>${sanitize(load.date)}</td>
              <td>${new Date(load.expires_at).toLocaleDateString()}</td>
              <td>${sanitize(load.cargo_type)}</td>
              <td>${load.weight} tons</td>
              <td><span class="status-badge ${isExpired ? 'status-expired' : 'status-available'}">${isExpired ? 'Expired' : 'Active'}</span></td>
              <td>
                  <button class="btn small" onclick="editUserLoad('${load.id}')">Edit</button>
                  <button class="btn small danger" onclick="deleteUserLoad('${load.id}')">Delete</button>
              </td>
          `;
          tbody.appendChild(row);
      });
      
      // Update UI based on access permissions
      await updateUIBasedOnAccess();
      
    } catch (error) {
      console.error('Error rendering transporter dashboard:', error);
      showNotification('Failed to load your loads', 'error');
    }
  };

  const renderMarket = async () => {
    try {
        const tbody = el('tableMarketLoads')?.querySelector('tbody');
        if (!tbody) return;
        
        // Clear table
        tbody.innerHTML = '';
        
        const loads = await getLoads();
        
        if (loads.length === 0) {
            const row = document.createElement('tr');
            const cell = document.createElement('td');
            cell.colSpan = 10;
            cell.className = 'muted';
            cell.textContent = 'No loads available in the market.';
            row.appendChild(cell);
            tbody.appendChild(row);
            return;
        }
        
        loads.forEach(load => {
            const row = document.createElement('tr');
            const isExpired = new Date(load.expires_at) < new Date();
            
            row.innerHTML = `
                <td>${sanitize(load.ref)}</td>
                <td>${sanitize(load.origin)}</td>
                <td>${sanitize(load.destination)}</td>
                <td>${sanitize(load.date)}</td>
                <td>${new Date(load.expires_at).toLocaleDateString()}</td>
                <td>${sanitize(load.cargo_type)}</td>
                <td>${load.weight} tons</td>
                <td><span class="status-badge ${isExpired ? 'status-expired' : 'status-available'}">${isExpired ? 'Expired' : 'Available'}</span></td>
                <td>${sanitize(load.shipper_name)} (${sanitize(load.shipper_membership)})</td>
                <td>
                    <button class="btn small" onclick="contactShipper('${load.shipper_membership}')">Contact</button>
                </td>
            `;
            tbody.appendChild(row);
        });
        
    } catch (error) {
        console.error('Error rendering market:', error);
        if (!error.message.includes('Access denied')) {
            showNotification('Failed to load market data', 'error');
        }
    }
  };

  const renderMessages = async () => {
    try {
      const messageContainer = el('messageContainer');
      if (!messageContainer) return;
      
      // Clear messages
      messageContainer.innerHTML = '';
      
      const messages = await getMessages();
      
      if (messages.length === 0) {
        const noMessages = document.createElement('div');
        noMessages.className = 'muted';
        noMessages.textContent = 'No messages yet.';
        messageContainer.appendChild(noMessages);
        return;
      }
      
      const user = getCurrentUserSync();
      
      messages.forEach(msg => {
        const messageDiv = document.createElement('div');
        const isSent = msg.sender_membership === user.membership_number;
        
        messageDiv.className = `message ${isSent ? 'message-sent' : 'message-received'}`;
        messageDiv.innerHTML = `
          <div class="message-header">
            <span class="message-sender">${isSent ? 'You' : sanitize(msg.sender_membership)}</span>
            <span class="message-time">${new Date(msg.created_at).toLocaleString()}</span>
          </div>
          <div class="message-body">${sanitize(msg.body)}</div>
        `;
        
        messageContainer.appendChild(messageDiv);
      });
      
    } catch (error) {
      console.error('Error rendering messages:', error);
      if (!error.message.includes('Access denied')) {
        showNotification('Failed to load messages', 'error');
      }
    }
  };

  const renderControl = async () => {
    const user = getCurrentUserSync();
    if (!user || !isAdmin(user)) {
        showNotification('Admin access required', 'error');
        return;
    }
    
    try {
        // Fetch users and loads for admin
        const [usersResponse, loadsResponse] = await Promise.all([
            apiRequest('/users'),
            apiRequest('/admin/loads')
        ]);

        if (!usersResponse.success || !loadsResponse.success) {
            throw new Error('Failed to fetch admin data');
        }

        const users = usersResponse.data.users;
        const loads = loadsResponse.data.loads;

        // Render users table
        const usersTbody = el('tableUsers')?.querySelector('tbody');
        if (usersTbody) {
            usersTbody.innerHTML = '';
            if (users.length === 0) {
                usersTbody.innerHTML = '<tr><td colspan="7" class="muted">No users found.</td></tr>';
            } else {
                // Fetch access permissions for each user to determine their actual status
                const usersWithAccess = await Promise.all(
                    users.map(async (user) => {
                        if (isAdmin(user)) {
                            return { ...user, accessStatus: 'full', permissions: { market: true, 'post-load': true, messages: true } };
                        }
                        
                        try {
                            const accessResponse = await apiRequest(`/admin/users/${user.id}/access`);
                            const permissions = accessResponse.success ? accessResponse.data.pages : {
                                market: { enabled: false },
                                'post-load': { enabled: false },
                                messages: { enabled: false }
                            };
                            
                            // Determine access status based on actual permissions
                            const hasMarketAccess = permissions.market?.enabled;
                            const hasPostLoadAccess = permissions['post-load']?.enabled;
                            const hasMessagesAccess = permissions.messages?.enabled;
                            
                            let accessStatus = 'restricted';
                            let accessClass = 'status-expired';
                            
                            if (hasMarketAccess && hasPostLoadAccess && hasMessagesAccess) {
                                accessStatus = 'full';
                                accessClass = 'status-available';
                            } else if (hasMarketAccess || hasPostLoadAccess || hasMessagesAccess) {
                                accessStatus = 'partial';
                                accessClass = 'status-partial';
                            }
                            
                            return { 
                                ...user, 
                                accessStatus, 
                                accessClass,
                                permissions 
                            };
                        } catch (error) {
                            console.error(`Error fetching access for user ${user.email}:`, error);
                            return { 
                                ...user, 
                                accessStatus: 'restricted', 
                                accessClass: 'status-expired',
                                permissions: { market: false, 'post-load': false, messages: false }
                            };
                        }
                    })
                );
                
                usersWithAccess.forEach(user => {
                    const row = document.createElement('tr');
                    const isCurrentSuperAdmin = user.email === SUPER_ADMIN_EMAIL;
                    
                    // Create access status badge with detailed tooltip
                    let accessBadge = '';
                    let accessDetails = '';
                    
                    if (user.accessStatus === 'full') {
                        accessBadge = '<span class="status-badge status-available">Full Access</span>';
                        accessDetails = 'Market: ✅ | Post Load: ✅ | Messages: ✅';
                    } else if (user.accessStatus === 'partial') {
                        accessBadge = '<span class="status-badge status-partial">Partial Access</span>';
                        const market = user.permissions.market?.enabled ? '✅' : '❌';
                        const postLoad = user.permissions['post-load']?.enabled ? '✅' : '❌';
                        const messages = user.permissions.messages?.enabled ? '✅' : '❌';
                        accessDetails = `Market: ${market} | Post Load: ${postLoad} | Messages: ${messages}`;
                    } else {
                        accessBadge = '<span class="status-badge status-expired">Restricted</span>';
                        accessDetails = 'Market: ❌ | Post Load: ❌ | Messages: ❌';
                    }
                    
                    row.innerHTML = `
                        <td>${sanitize(user.name)} ${isCurrentSuperAdmin ? '👑' : ''}</td>
                        <td>${sanitize(user.email)}</td>
                        <td>${sanitize(user.membership_number)}</td>
                        <td><span class="chip ${isCurrentSuperAdmin ? 'chip-warning' : ''}">${isCurrentSuperAdmin ? 'SUPER ADMIN' : sanitize(user.role)}</span></td>
                        <td>${new Date(user.created_at).toLocaleDateString()}</td>
                        <td>
                            ${accessBadge}
                            <div class="muted" style="font-size: 10px; margin-top: 2px;">${accessDetails}</div>
                        </td>
                        <td>
                            ${!isCurrentSuperAdmin ? `
                                <div class="flex-gap-8">
                                    <button class="btn small" onclick="editUserAccess('${user.id}')">Edit Access</button>
                                    <button class="btn small danger" onclick="deleteUser('${user.email}')">Delete</button>
                                </div>
                            ` : '<span class="muted">Protected</span>'}
                        </td>
                    `;
                    usersTbody.appendChild(row);
                });
            }
        }

        // Render loads table
        const loadsTbody = el('tableLoads')?.querySelector('tbody');
        if (loadsTbody) {
            loadsTbody.innerHTML = '';
            if (loads.length === 0) {
                loadsTbody.innerHTML = '<tr><td colspan="8" class="muted">No loads found.</td></tr>';
            } else {
                loads.forEach(load => {
                    const statusClass = load.is_expired ? 'status-expired' : 'status-available';
                    const statusText = load.is_expired ? 'Expired' : 'Active';
                    
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${sanitize(load.ref)}</td>
                        <td>${sanitize(load.origin)}</td>
                        <td>${sanitize(load.destination)}</td>
                        <td>${sanitize(load.date)}</td>
                        <td>${sanitize(load.cargo_type)}</td>
                        <td>${load.weight} tons</td>
                        <td>${sanitize(load.shipper_name)} (${sanitize(load.shipper_membership)})</td>
                        <td><span class="status-badge ${statusClass}">${statusText}</span></td>
                    `;
                    loadsTbody.appendChild(row);
                });
            }
        }

        // Populate user dropdowns for access control and password reset
        const selectUserForAccess = el('selectUserForAccess');
        const selectUserForPassword = el('selectUserForPassword');
        
        [selectUserForAccess, selectUserForPassword].forEach(select => {
            if (select) {
                // Clear existing options except the first one
                while (select.children.length > 1) {
                    select.removeChild(select.lastChild);
                }
                
                users.forEach(user => {
                  if (user.email !== SUPER_ADMIN_EMAIL) { // Don't include super admin in dropdowns
                    const option = document.createElement('option');
                    option.value = user.id;
                    option.textContent = `${user.name} (${user.email}) - ${user.role}`;
                    select.appendChild(option);
                  }
                });
            }
        });

        // Reset toggles when control panel loads
        resetToggles();

        // Show super admin badge
        if (isSuperAdmin(user)) {
          const adminTitle = document.querySelector('#page-control h2');
          if (adminTitle) {
            adminTitle.innerHTML = 'Super Admin Control Panel 👑';
          }
        }

        showNotification('Admin panel loaded successfully', 'success');
    } catch (error) {
        console.error('Error rendering control panel:', error);
        
        if (error.message.includes('403') || error.message.includes('Access denied')) {
            showNotification('Admin access denied. Please check your permissions.', 'error');
        } else if (error.message.includes('401') || error.message.includes('Authentication')) {
            showNotification('Please log in again', 'error');
            setTimeout(() => {
                location.hash = '#login';
            }, 2000);
        } else {
            showNotification('Failed to load admin data', 'error');
        }
    }
  };

  // Add this function to quickly edit a user's access
  window.editUserAccess = async (userId) => {
    // Find the user in the dropdown and select them
    const select = el('selectUserForAccess');
    if (select) {
      for (let i = 0; i < select.options.length; i++) {
        if (select.options[i].value === userId) {
          select.selectedIndex = i;
          await loadUserAccess(userId);
          showNotification(`Loaded access for selected user`, 'info');
          return;
        }
      }
    }
    showNotification('User not found in dropdown', 'error');
  };

  // Admin access control functions
  window.loadUserAccess = async () => {
    const userId = el('selectUserForAccess').value;
    if (!userId) {
      showNotification('Please select a user first', 'error');
      return;
    }
    
    // Show loading state
    setButtonLoading(el('btnLoadUserAccess'), true);
    await loadUserAccess(userId);
    setButtonLoading(el('btnLoadUserAccess'), false);
  };

  window.saveUserAccess = async () => {
    const userId = el('selectUserForAccess').value;
    if (!userId) {
      showNotification('Please select a user first', 'error');
      return;
    }
    
    // Show loading state
    setButtonLoading(el('btnSaveUserAccess'), true);
    const success = await saveUserAccess(userId);
    setButtonLoading(el('btnSaveUserAccess'), false);
    
    if (success) {
      showNotification(`Access permissions updated successfully! The user will see the changes immediately.`, 'success');
      // Refresh the control panel to show updated status
      await renderControl();
    }
  };

  window.enableAllAccess = () => {
    if (!el('selectUserForAccess').value) {
      showNotification('Please select a user first', 'error');
      return;
    }
    el('access-market').checked = true;
    el('access-post-load').checked = true;
    el('access-messages').checked = true;
    showNotification('All access enabled - remember to save', 'info');
  };

  window.disableAllAccess = () => {
    if (!el('selectUserForAccess').value) {
      showNotification('Please select a user first', 'error');
      return;
    }
    el('access-market').checked = false;
    el('access-post-load').checked = false;
    el('access-messages').checked = false;
    showNotification('All access disabled - remember to save', 'info');
  };

  // Toggle switch event handlers
  const setupToggleSwitches = () => {
    const toggleSwitches = document.querySelectorAll('.toggle-switch input[type="checkbox"]');
    toggleSwitches.forEach(switchElement => {
      switchElement.addEventListener('change', function() {
        const userId = el('selectUserForAccess').value;
        if (!userId) {
          // If no user selected, revert the toggle and show error
          this.checked = !this.checked;
          showNotification('Please select a user and click "Load Access" first', 'error');
          return;
        }
        
        // Visual feedback for change
        const toggleParent = this.closest('.toggle-switch');
        toggleParent.classList.add('loading');
        setTimeout(() => {
          toggleParent.classList.remove('loading');
        }, 300);
        
        console.log(`Toggle ${this.id} changed to: ${this.checked} for user: ${userId}`);
      });
    });
  };

  // Enhanced load user access function
  const loadUserAccess = async (userId) => {
    try {
      const response = await apiRequest(`/admin/users/${userId}/access`);
      if (response.success) {
        const accessData = response.data.pages || {
          market: { enabled: false },
          'post-load': { enabled: false },
          messages: { enabled: false }
        };
        
        // Update toggle switches
        el('access-market').checked = accessData.market?.enabled || false;
        el('access-post-load').checked = accessData['post-load']?.enabled || false;
        el('access-messages').checked = accessData.messages?.enabled || false;
        
        // Update the select dropdown to show which user is being edited
        const select = el('selectUserForAccess');
        const selectedOption = select.options[select.selectedIndex];
        showNotification(`Loaded access permissions for: ${selectedOption.text}`, 'success');
        
        // Enable the save button
        el('btnSaveUserAccess').disabled = false;
      }
    } catch (error) {
      console.error('Error loading user access:', error);
      showNotification('Failed to load user access permissions', 'error');
      // Reset toggles on error
      resetToggles();
    }
  };

  // Enhanced save user access function
  const saveUserAccess = async (userId) => {
    try {
      const accessData = {
        market: { enabled: el('access-market').checked },
        'post-load': { enabled: el('access-post-load').checked },
        messages: { enabled: el('access-messages').checked }
      };
      
      const response = await apiRequest(`/admin/users/${userId}/access`, {
        method: 'PUT',
        body: JSON.stringify({ pages: accessData })
      });
      
      if (response.success) {
        const select = el('selectUserForAccess');
        const selectedOption = select.options[select.selectedIndex];
        
        // Update user table to reflect changes
        await renderControl();
        return true;
      }
      return false;
    } catch (error) {
      console.error('Error saving user access:', error);
      showNotification('Failed to update user access permissions', 'error');
      return false;
    }
  };

  // Reset all toggles to default state
  const resetToggles = () => {
    const toggles = {
      'access-market': false,
      'access-post-load': false,
      'access-messages': false
    };
    
    Object.keys(toggles).forEach(toggleId => {
      const toggle = el(toggleId);
      if (toggle) {
        toggle.checked = toggles[toggleId];
      }
    });
    
    // Disable save button until user is selected
    el('btnSaveUserAccess').disabled = true;
  };

  // Global functions for onclick handlers
  window.editUserLoad = async (loadId) => {
    showNotification('Edit functionality coming soon', 'info');
  };
  
  window.deleteUserLoad = async (loadId) => {
    if (confirm('Are you sure you want to delete this load?')) {
      await handleError(async () => {
        await deleteLoad(loadId);
        await render();
      }, 'Failed to delete load');
    }
  };

  window.deleteUser = async (email) => {
    if (email === SUPER_ADMIN_EMAIL) {
      showNotification('Cannot delete Super Admin account', 'error');
      return;
    }
    
    if (confirm(`Are you sure you want to delete user ${email}? This will also delete all their loads and messages.`)) {
      await handleError(async () => {
        const response = await apiRequest(`/admin/users/${encodeURIComponent(email)}`, {
          method: 'DELETE'
        });
        
        if (response.success) {
          showNotification('User deleted successfully', 'success');
          await renderControl();
        } else {
          throw new Error(response.error);
        }
      }, 'Failed to delete user');
    }
  };
  
  window.contactShipper = (membershipNumber) => {
    location.hash = '#messages';
    setTimeout(() => {
      const msgTo = el('msgTo');
      if (msgTo) {
        msgTo.value = membershipNumber;
        msgTo.focus();
      }
    }, 100);
  };

  // Profile rendering functions
  const renderShipperProfile = async () => {
    const user = getCurrentUserSync();
    if (!user || (user.role !== 'shipper' && !isAdmin(user))) return;
    
    setText('shipperProfileName', user.name);
    setText('shipperProfileEmail', user.email);
    setText('shipperProfileMembership', user.membership_number);
    setText('shipperProfileCompany', user.company || 'Not provided');
    setText('shipperProfilePhone', user.phone || 'Not provided');
    setText('shipperProfileAddress', user.address || 'Not provided');
    setText('shipperProfileRole', isSuperAdmin(user) ? 'Super Admin' : user.role);
    setText('shipperProfileCreated', new Date(user.created_at).toLocaleDateString());
    setText('shipperProfileSince', new Date(user.created_at).toLocaleDateString());
    
    // Set avatar initial
    const avatar = el('shipperProfileAvatar');
    if (avatar) {
      avatar.textContent = user.name.charAt(0).toUpperCase();
    }
    
    // Pre-fill form fields
    el('profileShipperName').value = user.name;
    el('profileShipperPhone').value = user.phone || '';
    el('profileShipperAddress').value = user.address || '';
  };

  const renderTransporterProfile = async () => {
    const user = getCurrentUserSync();
    if (!user || (user.role !== 'transporter' && !isAdmin(user))) return;
    
    setText('transporterProfileName', user.name);
    setText('transporterProfileEmail', user.email);
    setText('transporterProfileMembership', user.membership_number);
    setText('transporterProfileCompany', user.company || 'Not provided');
    setText('transporterProfileVehicle', user.vehicle_info || 'Not provided');
    setText('transporterProfilePhone', user.phone || 'Not provided');
    setText('transporterProfileAddress', user.address || 'Not provided');
    setText('transporterProfileRole', isSuperAdmin(user) ? 'Super Admin' : user.role);
    setText('transporterProfileCreated', new Date(user.created_at).toLocaleDateString());
    setText('transporterProfileSince', new Date(user.created_at).toLocaleDateString());
    
    // Set avatar initial
    const avatar = el('transporterProfileAvatar');
    if (avatar) {
      avatar.textContent = user.name.charAt(0).toUpperCase();
    }
    
    // Pre-fill form fields
    el('profileTransporterName').value = user.name;
    el('profileTransporterPhone').value = user.phone || '';
    el('profileTransporterAddress').value = user.address || '';
  };
    
  const renderHeader = async () => {
    const user = getCurrentUserSync();
    const navLinks = el('navLinks');
    const authUser = el('authUser');
    const btnLoginNav = el('btnLoginNav');
    const btnLogout = el('btnLogout');
    const roleChip = el('roleChip');
    
    if (user) {
      // Clear existing nav links
      if (navLinks) {
        navLinks.innerHTML = '';
      }
      
      if (authUser) authUser.textContent = isSuperAdmin(user) ? `${user.name} 👑` : user.name;
      if (btnLoginNav) btnLoginNav.classList.add('hidden');
      if (btnLogout) btnLogout.classList.remove('hidden');
      if (roleChip) {
        roleChip.textContent = isSuperAdmin(user) ? 'SUPER ADMIN' : user.role;
        roleChip.classList.remove('hidden');
        if (isSuperAdmin(user)) {
          roleChip.classList.add('chip-warning');
        }
      }
      
      // Create navigation links based on role and permissions
      const links = [];
      
      if (user.role === 'shipper' || isAdmin(user)) {
        links.push(
          { href: '#shipper-dashboard', text: 'Dashboard' }
        );
        
        // Only show these links if user has access - ALWAYS check fresh permissions
        const marketAccess = await hasAccessTo('market');
        const postLoadAccess = await hasAccessTo('post-load');
        const messagesAccess = await hasAccessTo('messages');
        
        if (postLoadAccess) {
          links.push({ href: '#shipper-post', text: 'Post Load' });
        }
        if (marketAccess) {
          links.push({ href: '#market', text: 'Market' });
        }
        if (messagesAccess) {
          links.push({ href: '#messages', text: 'Messages' });
        }
        
        links.push({ href: '#shipper-profile', text: 'Profile' });
        
        // Remove duplicates and add to navigation
        const uniqueLinks = links.filter((link, index, self) => 
          index === self.findIndex(l => l.href === link.href)
        );
        
        // Add links to navigation
        uniqueLinks.forEach(link => {
          const a = document.createElement('a');
          a.className = 'btn ghost';
          a.href = link.href;
          a.textContent = link.text;
          if (navLinks) {
            navLinks.appendChild(a);
          }
        });
      }
      
      if (user.role === 'transporter' || isAdmin(user)) {
        links.push(
          { href: '#transporter-dashboard', text: 'Transporter Dashboard' }
        );
        
        const marketAccess = await hasAccessTo('market');
        const postLoadAccess = await hasAccessTo('post-load');
        const messagesAccess = await hasAccessTo('messages');
        
        if (postLoadAccess) {
          links.push({ href: '#shipper-post', text: 'Post Load' });
        }
        if (marketAccess) {
          links.push({ href: '#market', text: 'Market' });
        }
        if (messagesAccess) {
          links.push({ href: '#messages', text: 'Messages' });
        }
        
        if (!links.find(link => link.href === '#shipper-profile')) {
          links.push({ href: '#transporter-profile', text: 'Profile' });
        }
        
        // Remove duplicates and add to navigation
        const uniqueLinks = links.filter((link, index, self) => 
          index === self.findIndex(l => l.href === link.href)
        );
        
        // Add links to navigation
        uniqueLinks.forEach(link => {
          const a = document.createElement('a');
          a.className = 'btn ghost';
          a.href = link.href;
          a.textContent = link.text;
          if (navLinks) {
            navLinks.appendChild(a);
          }
        });
      }
      
      if (isAdmin(user)) {
        const adminLink = document.createElement('a');
        adminLink.className = 'btn ghost';
        adminLink.href = '#control';
        adminLink.textContent = 'Admin Control';
        if (navLinks) {
          navLinks.appendChild(adminLink);
        }
      }
    } else {
      // User not logged in
      if (navLinks) {
        navLinks.innerHTML = '';
      }
      
      if (authUser) authUser.textContent = '';
      if (btnLoginNav) btnLoginNav.classList.remove('hidden');
      if (btnLogout) btnLogout.classList.add('hidden');
      if (roleChip) roleChip.classList.add('hidden');
    }
  };

  // Main render function
  const render = async () => {
    await handleError(async () => {
      await renderHeader();
      
      // Hide all pages first
      document.querySelectorAll('section').forEach(s => {
        if (s.id && s.id.startsWith('page-')) {
          s.classList.add('hidden');
        }
      });
      
      const hash = location.hash.slice(1) || 'index';
      const user = getCurrentUserSync();
      
      // Check access
      let canAccess = false;
      if (hash === 'index' || hash === 'login' || hash === 'register-options' || 
          hash === 'register-shipper' || hash === 'register-transporter') {
        canAccess = true;
      } else if (user) {
        canAccess = await canAccessPage(user, hash);
      }
      
      if (!canAccess) {
        if (user) {
          // Show access denied message
          if (hash === 'market' || hash === 'shipper-post' || hash === 'messages') {
            showNotification('Access denied. Please contact administrator for access.', 'error');
          }
          
          location.hash = isAdmin(user) ? '#control' : 
                         user.role === 'shipper' ? '#shipper-dashboard' : '#transporter-dashboard';
        } else {
          location.hash = '#login';
        }
        return;
      }
      
      // Show the appropriate page
      const pageElement = el(`page-${hash}`);
      if (pageElement) {
        pageElement.classList.remove('hidden');
      }
      
      // Render page-specific content
      switch(hash) {
        case 'shipper-dashboard':
          await renderShipperDashboard();
          break;
        case 'transporter-dashboard':
          await renderTransporterDashboard();
          break;
        case 'market':
          await renderMarket();
          break;
        case 'messages':
          await renderMessages();
          break;
        case 'control':
          await renderControl();
          break;
        case 'shipper-profile':
          await renderShipperProfile();
          break;
        case 'transporter-profile':
          await renderTransporterProfile();
          break;
      }
    }, 'Failed to render page');
  };

  // Event handlers
  const init = () => {
    console.log('MakiwaFreight app initializing...');
    
    // Form submissions
    el('formLogin')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = el('loginEmail')?.value;
      const password = el('loginPassword')?.value;
      
      if (!email || !password) {
        showNotification('Please fill in all fields', 'error');
        return;
      }
      
      const submitButton = e.target.querySelector('button[type="submit"]');
      setButtonLoading(submitButton, true);
      
      await handleError(async () => {
        const user = await login(email, password);
        if (user) {
          // Redirect based on role
          if (isAdmin(user)) {
            location.hash = '#control';
          } else if (user.role === 'shipper') {
            location.hash = '#shipper-dashboard';
          } else {
            location.hash = '#transporter-dashboard';
          }
        }
      }, 'Login failed');
      
      setButtonLoading(submitButton, false);
    });
    
    el('formRegShipper')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const formData = new FormData(e.target);
      const data = Object.fromEntries(formData);
      data.role = 'shipper';
      
      const submitButton = e.target.querySelector('button[type="submit"]');
      setButtonLoading(submitButton, true);
      
      await handleError(async () => {
        await registerUser(data);
        const user = getCurrentUserSync();
        if (isAdmin(user)) {
          location.hash = '#control';
        } else {
          location.hash = '#shipper-dashboard';
        }
      }, 'Registration failed');
      
      setButtonLoading(submitButton, false);
    });
    
    el('formRegTransporter')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const formData = new FormData(e.target);
      const data = Object.fromEntries(formData);
      data.role = 'transporter';
      
      const submitButton = e.target.querySelector('button[type="submit"]');
      setButtonLoading(submitButton, true);
      
      await handleError(async () => {
        await registerUser(data);
        const user = getCurrentUserSync();
        if (isAdmin(user)) {
          location.hash = '#control';
        } else {
          location.hash = '#transporter-dashboard';
        }
      }, 'Registration failed');
      
      setButtonLoading(submitButton, false);
    });
    
    el('formPostLoad')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const formData = new FormData(e.target);
      const data = Object.fromEntries(formData);
      
      const submitButton = e.target.querySelector('button[type="submit"]');
      setButtonLoading(submitButton, true);
      
      await handleError(async () => {
        await postLoad(data);
        e.target.reset();
        const user = getCurrentUserSync();
        if (isAdmin(user)) {
          location.hash = '#control';
        } else {
          location.hash = user?.role === 'shipper' ? '#shipper-dashboard' : '#transporter-dashboard';
        }
      }, 'Failed to post load');
      
      setButtonLoading(submitButton, false);
    });
    
    el('formSendMsg')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const to = el('msgTo')?.value;
      const body = el('msgBody')?.value;
      
      if (!to || !body) {
        showNotification('Please fill in all fields', 'error');
        return;
      }
      
      const submitButton = e.target.querySelector('button[type="submit"]');
      setButtonLoading(submitButton, true);
      
      await handleError(async () => {
        await sendMessage(to, body);
        e.target.reset();
        await renderMessages();
      }, 'Failed to send message');
      
      setButtonLoading(submitButton, false);
    });
    
    el('btnLogout')?.addEventListener('click', logout);
    
    // Profile update handlers
    el('saveProfileShipper')?.addEventListener('click', async () => {
      const name = el('profileShipperName')?.value;
      const phone = el('profileShipperPhone')?.value;
      const address = el('profileShipperAddress')?.value;
      const password = el('profileShipperPassword')?.value;
      
      const profileData = {};
      if (name) profileData.name = name;
      if (phone) profileData.phone = phone;
      if (address) profileData.address = address;
      if (password) profileData.password = password;
      
      setButtonLoading(el('saveProfileShipper'), true);
      await handleError(async () => {
        await updateUserProfile(profileData);
        await renderShipperProfile();
      }, 'Failed to update profile');
      setButtonLoading(el('saveProfileShipper'), false);
    });
    
    el('saveProfileTransporter')?.addEventListener('click', async () => {
      const name = el('profileTransporterName')?.value;
      const phone = el('profileTransporterPhone')?.value;
      const address = el('profileTransporterAddress')?.value;
      const password = el('profileTransporterPassword')?.value;
      
      const profileData = {};
      if (name) profileData.name = name;
      if (phone) profileData.phone = phone;
      if (address) profileData.address = address;
      if (password) profileData.password = password;
      
      setButtonLoading(el('saveProfileTransporter'), true);
      await handleError(async () => {
        await updateUserProfile(profileData);
        await renderTransporterProfile();
      }, 'Failed to update profile');
      setButtonLoading(el('saveProfileTransporter'), false);
    });
    
    // Admin access control handlers
    el('btnLoadUserAccess')?.addEventListener('click', window.loadUserAccess);
    el('btnSaveUserAccess')?.addEventListener('click', window.saveUserAccess);
    
    // Setup toggle switches
    setupToggleSwitches();
    
    // Initialize the app
    render();
    window.addEventListener('hashchange', render);
    
    console.log('MakiwaFreight app initialized successfully');
  };
  
  // Start the application
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
