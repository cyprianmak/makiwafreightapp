// MakiwaFreight App Frontend (External JavaScript File) - BROWSER COMPATIBLE
(function() {
  'use strict';
  
  // Configuration
  const API_BASE = '/api';
  const LOAD_EXPIRY_DAYS = 7;
  const SESSION_TIMEOUT_MINUTES = 30;
  const SESSION_WARNING_MINUTES = 5;
  
  // Page definitions for access control
  const PAGES = {
    'shipper-dashboard': { name: 'Shipper Dashboard', roles: ['shipper'] },
    'shipper-post': { name: 'Post Load', roles: ['admin', 'shipper', 'transporter'] },
    'shipper-profile': { name: 'Shipper Profile', roles: ['shipper'] },
    'transporter-dashboard': { name: 'Transporter Dashboard', roles: ['transporter'] },
    'transporter-profile': { name: 'Transporter Profile', roles: ['transporter'] },
    'market': { name: 'Market', roles: ['shipper', 'transporter'] },
    'messages': { name: 'Messages', roles: ['shipper', 'transporter'] },
    'control': { name: 'Admin Control', roles: ['admin'] }
  };
  
  // Access control page mapping
  const ACCESS_PAGES = {
    'market': { name: 'Market Page', id: 'access-market' },
    'shipper-post': { name: 'Post Load Page', id: 'access-post-load' }
  };
  
  // Role definitions
  const ROLES = ['admin', 'shipper', 'transporter'];
  
  // Session timeout variables
  let sessionTimeout;
  let sessionWarningTimeout;
  let lastActivityTime = Date.now();
  
  // Utility functions
  const now = () => new Date().toISOString();
  const el = id => document.getElementById(id);
  const setText = (id, txt) => { const e = el(id); if(e) e.textContent = txt; };
  const setHidden = (id, hid) => { const e = el(id); if(e) e.classList[hid ? 'add' : 'remove']('hidden'); };
  
  // Sanitize input to prevent XSS
  const sanitize = str => {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  };
  
  // Validate email format
  const isValidEmail = email => {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
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
  
  // Calculate expiry date (7 days from now)
  const calculateExpiryDate = () => {
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + LOAD_EXPIRY_DAYS);
    return expiryDate.toISOString();
  };
  
  // Check if a load has expired
  const isLoadExpired = load => {
    if (!load.expires_at) return false;
    return new Date(load.expires_at) < new Date();
  };
  
  // Get load status
  const getLoadStatus = load => {
    if (load.secured_by) return 'secured';
    if (isLoadExpired(load)) return 'expired';
    return 'available';
  };
  
  // Get status badge HTML
  const getStatusBadge = status => {
    const statusMap = {
      'available': { class: 'status-available', text: 'Available' },
      'secured': { class: 'status-secured', text: 'Secured' },
      'expired': { class: 'status-expired', text: 'Expired' }
    };
    
    const statusInfo = statusMap[status] || statusMap.available;
    return `<span class="status-badge ${statusInfo.class}">${statusInfo.text}</span>`;
  };
  
  // Get current user synchronously (from stored data)
  const getCurrentUserSync = () => {
    try {
      const userData = sessionStorage.getItem('currentUser');
      if (userData) {
        return JSON.parse(userData);
      }
      return null;
    } catch (error) {
      console.error('Error getting current user:', error);
      return null;
    }
  };
  
  // Show loading state on a button
  const setButtonLoading = (buttonId, isLoading) => {
    const button = el(buttonId);
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
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    
    const container = document.getElementById('notificationContainer');
    if (!container) {
      console.error('Notification container not found');
      return;
    }
    
    container.appendChild(notification);
    
    // Use requestAnimationFrame instead of setTimeout for animation
    requestAnimationFrame(() => {
      notification.classList.add('show');
    });
    
    // Store timeout ID for cleanup
    const timeoutId = setTimeout(() => {
      notification.classList.remove('show');
      const removeTimeoutId = setTimeout(() => {
        if (notification.parentNode) {
          notification.remove();
        }
      }, 300);
      notification.dataset.removeTimeoutId = removeTimeoutId;
    }, 5000);
    
    notification.dataset.timeoutId = timeoutId;
  }
  
  // Session timeout management
  const resetSessionTimer = () => {
    lastActivityTime = Date.now();
    clearTimeout(sessionTimeout);
    clearTimeout(sessionWarningTimeout);
    
    // Set warning timeout (5 minutes before session expires)
    sessionWarningTimeout = setTimeout(showSessionWarning, (SESSION_TIMEOUT_MINUTES - SESSION_WARNING_MINUTES) * 60 * 1000);
    
    // Set actual session timeout
    sessionTimeout = setTimeout(logoutDueToInactivity, SESSION_TIMEOUT_MINUTES * 60 * 1000);
  };
  
  const showSessionWarning = () => {
    const modal = el('sessionTimeoutModal');
    const timer = el('sessionTimer');
    
    if (!modal || !timer) return;
    
    let timeLeft = SESSION_WARNING_MINUTES * 60; // 5 minutes in seconds
    
    const updateTimer = () => {
      const minutes = Math.floor(timeLeft / 60);
      const seconds = timeLeft % 60;
      timer.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
      
      if (timeLeft > 0) {
        timeLeft--;
        timer.dataset.updateTimerId = setTimeout(updateTimer, 1000);
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
      // Clear any running timers
      const timer = el('sessionTimer');
      if (timer && timer.dataset.updateTimerId) {
        clearTimeout(parseInt(timer.dataset.updateTimerId));
      }
      modal.classList.add('hidden');
    }
    resetSessionTimer();
    showNotification('Session extended', 'success');
  };
  
  // Set up session timeout event listeners
  const setupSessionTimeout = () => {
    // Reset timer on user activity
    const activityEvents = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'];
    activityEvents.forEach(event => {
      document.addEventListener(event, resetSessionTimer, false);
    });
    
    // Set up session timeout modal buttons
    const extendBtn = el('extendSession');
    const logoutBtn = el('logoutSession');
    if (extendBtn) extendBtn.addEventListener('click', extendSession);
    if (logoutBtn) logoutBtn.addEventListener('click', logout);
    
    // Initialize the timer
    resetSessionTimer();
  };
  
  // API helper functions that call correct backend endpoints
  const apiRequest = async (endpoint, options = {}) => {
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers
    };
    
    // Add authorization header if user is logged in
    const user = getCurrentUserSync();
    if (user && user.data && user.data.token) {
      headers['Authorization'] = `Bearer ${user.data.token}`;
    }
    
    try {
      const response = await fetch(`${API_BASE}${endpoint}`, {
        ...options,
        headers
      });
      
      // Check for rate limiting
      if (response.status === 429) {
        showRateLimitWarning();
        throw new Error('Rate limit exceeded. Please try again later.');
      }
      
      if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new Error(error.error || `API error: ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      if (error instanceof TypeError && error.message.includes('fetch')) {
        throw new Error('Network error. Please check your connection and try again.');
      }
      throw error;
    }
  };
  
  // Rate limiting warning
  const showRateLimitWarning = () => {
    const warnings = [
      'rateLimitWarningShipper',
      'rateLimitWarningTransporter', 
      'rateLimitWarningMarket'
    ];
    
    warnings.forEach(warningId => {
      const warning = el(warningId);
      if (warning) {
        warning.textContent = 'Rate limit exceeded. Please slow down your requests.';
        warning.classList.remove('hidden');
        
        // Use proper timeout storage
        const timeoutId = setTimeout(() => {
          warning.classList.add('hidden');
        }, 10000);
        warning.dataset.timeoutId = timeoutId;
      }
    });
  };
  
  // Authentication API functions
  const login = async (email, password) => {
    if (!email || !password) return null;
    email = email.trim().toLowerCase();
    try {
      const user = await apiRequest('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password })
      });
      if (user) {
        sessionStorage.setItem('currentUser', JSON.stringify(user));
        showNotification('Login successful', 'success');
        setupSessionTimeout(); // Start session timeout tracking
        return user;
      }
      return null;
    } catch (error) {
      console.error('Login error:', error);
      showNotification('Login failed: ' + error.message, 'error');
      return null;
    }
  };
  
  const logout = () => {
    // Clear all timeouts
    clearTimeout(sessionTimeout);
    clearTimeout(sessionWarningTimeout);
    
    // Clear notification timeouts
    document.querySelectorAll('.notification').forEach(notification => {
      if (notification.dataset.timeoutId) {
        clearTimeout(parseInt(notification.dataset.timeoutId));
      }
      if (notification.dataset.removeTimeoutId) {
        clearTimeout(parseInt(notification.dataset.removeTimeoutId));
      }
    });
    
    // Clear session timer if exists
    const timer = el('sessionTimer');
    if (timer && timer.dataset.updateTimerId) {
      clearTimeout(parseInt(timer.dataset.updateTimerId));
    }
    
    sessionStorage.removeItem('currentUser');
    showNotification('Logged out successfully', 'info');
    location.hash = '#login';
    render();
  };
  
  // User API functions
  const registerUser = async (data) => {
    if (!data.name || !data.email || !data.password || !data.phone) {
      throw new Error('All required fields must be filled');
    }
    if (!isValidEmail(data.email)) {
      throw new Error('Please enter a valid email address');
    }

    const sanitizedData = {
      name: sanitize(data.name),
      company: sanitize(data.company || ''),
      email: data.email.trim().toLowerCase(),
      phone: sanitize(data.phone),
      password: data.password,
      address: sanitize(data.address || ''),
      role: data.role,
      vehicle_info: sanitize(data.vehicle_info || '')
    };

    try {
      const response = await apiRequest('/auth/register', {
        method: 'POST',
        body: JSON.stringify(sanitizedData)
      });

      const membershipNumber = (response && response.data && response.data.user && response.data.user.membership_number)
        || response.membership_number
        || (response.data && response.data.user && response.data.user.membership_number);

      // Show membership number to user in UI
      if (sanitizedData.role === 'shipper') {
        const shipperMembershipEl = el('shipperMembershipNumber');
        if (shipperMembershipEl && membershipNumber) {
          shipperMembershipEl.textContent = `Your Membership Number: ${membershipNumber}`;
          shipperMembershipEl.classList.remove('display-none');
        }
      } else if (sanitizedData.role === 'transporter') {
        const transporterMembershipEl = el('transporterMembershipNumber');
        if (transporterMembershipEl && membershipNumber) {
          transporterMembershipEl.textContent = `Your Membership Number: ${membershipNumber}`;
          transporterMembershipEl.classList.remove('display-none');
        }
      }

      showNotification(`Registration successful! Your membership number is ${membershipNumber}`, 'success');

      if (response && response.data) {
        sessionStorage.setItem('currentUser', JSON.stringify(response));
        setupSessionTimeout(); // Start session timeout tracking
      }

      return response;
    } catch (error) {
      console.error('Registration error:', error);
      showNotification('Registration failed: ' + error.message, 'error');
      throw error;
    }
  };
  
  const updateUserProfile = async (profileData) => {
    if (!profileData) throw new Error('Profile data is required');
    const sanitizedData = {};
    for (const key in profileData) {
      if (['name', 'phone', 'address', 'password', 'company', 'vehicle_info'].includes(key)) {
        sanitizedData[key] = profileData[key];
      }
    }
    try {
      const user = await apiRequest('/users/me', {
        method: 'PUT',
        body: JSON.stringify(sanitizedData)
      });
      const currentUser = getCurrentUserSync();
      if (currentUser) {
        const updatedUser = { ...currentUser, ...sanitizedData };
        sessionStorage.setItem('currentUser', JSON.stringify(updatedUser));
      }
      showNotification('Profile updated successfully', 'success');
      return user;
    } catch (error) {
      console.error('Profile update error:', error);
      showNotification('Profile update failed: ' + error.message, 'error');
      throw error;
    }
  };
  
  // Get user's posted loads
  const getUserLoads = async () => {
    try {
      const response = await apiRequest('/users/me/loads');
      return response.data ? response.data.loads : response;
    } catch (error) {
      console.error('Get user loads error:', error);
      showNotification('Failed to get your loads', 'error');
      throw error;
    }
  };
  
  // Load API functions
  const postLoad = async (payload) => {
    if (!payload.origin || !payload.destination || !payload.date || !payload.cargo_type || !payload.weight) {
      throw new Error('All required fields must be filled');
    }
    const user = getCurrentUserSync();
    if (!user) throw new Error('User not logged in');
    
    const ref = 'LD' + Date.now().toString().slice(-6);
    const sanitizedPayload = {
      ref: ref,
      origin: sanitize(payload.origin),
      destination: sanitize(payload.destination),
      date: payload.date,
      cargo_type: sanitize(payload.cargo_type),
      weight: parseFloat(payload.weight),
      notes: sanitize(payload.notes || '')
    };
    try {
      const load = await apiRequest('/loads', {
        method: 'POST',
        body: JSON.stringify(sanitizedPayload)
      });
      showNotification('Load posted successfully', 'success');
      return load;
    } catch (error) {
      console.error('Post load error:', error);
      showNotification('Failed to post load: ' + error.message, 'error');
      throw error;
    }
  };
  
  const getLoads = async (filters = {}) => {
    try {
      const response = await apiRequest('/loads');
      let loads = response.data ? response.data.loads : response;
      
      // Filter expired loads and auto-delete them
      const now = new Date();
      const validLoads = [];
      const expiredLoads = [];
      
      loads.forEach(load => {
        if (isLoadExpired(load)) {
          expiredLoads.push(load);
        } else {
          validLoads.push(load);
        }
      });
      
      // Auto-delete expired loads
      if (expiredLoads.length > 0) {
        for (const load of expiredLoads) {
          try {
            await apiRequest(`/loads/${load.id}`, { method: 'DELETE' });
          } catch (error) {
            console.error('Error auto-deleting expired load:', error);
          }
        }
      }
      
      let filteredLoads = validLoads;
      
      if (filters.shipper_id) {
        filteredLoads = filteredLoads.filter(l => l.shipper_id === filters.shipper_id);
      }
      if (filters.origin) {
        filteredLoads = filteredLoads.filter(l => l.origin.toLowerCase().includes(filters.origin.toLowerCase()));
      }
      if (filters.destination) {
        filteredLoads = filteredLoads.filter(l => l.destination.toLowerCase().includes(filters.destination.toLowerCase()));
      }
      return filteredLoads;
    } catch (error) {
      console.error('Get loads error:', error);
      showNotification('Failed to get loads: ' + error.message, 'error');
      throw error;
    }
  };
  
  const updateLoad = async (loadId, patch) => {
    if (!loadId) throw new Error('Load ID is required');
    
    // Check if load object has id property
    if (!loadId || typeof loadId !== 'string') {
      console.error('Invalid load ID:', loadId);
      throw new Error('Invalid load ID provided');
    }
    
    const sanitizedPatch = {};
    for (const key in patch) {
      if (key === 'weight') {
        sanitizedPatch[key] = parseFloat(patch[key]);
      } else {
        sanitizedPatch[key] = sanitize(patch[key]);
      }
    }
    try {
      const load = await apiRequest(`/loads/${loadId}`, {
        method: 'PUT',
        body: JSON.stringify(sanitizedPatch)
      });
      showNotification('Load updated successfully', 'success');
      return load;
    } catch (error) {
      console.error('Update load error:', error);
      showNotification('Failed to update load: ' + error.message, 'error');
      throw error;
    }
  };
  
  const deleteLoad = async (loadId) => {
    if (!loadId) throw new Error('Load ID is required');
    try {
      await apiRequest(`/loads/${loadId}`, { method: 'DELETE' });
      showNotification('Load deleted successfully', 'success');
    } catch (error) {
      console.error('Delete load error:', error);
      showNotification('Failed to delete load: ' + error.message, 'error');
      throw error;
    }
  };
  
  // Message API functions
  const sendMessage = async (toMembership, body) => {
    if (!toMembership || !body) {
      throw new Error('Recipient and message are required');
    }
    const user = getCurrentUserSync();
    if (!user) throw new Error('User not logged in');
    
    try {
      const senderMembership = user.data.user.membership_number || 'Admin';
      const message = await apiRequest('/messages', {
        method: 'POST',
        body: JSON.stringify({ 
          recipient_membership: toMembership, 
          body: sanitize(body) 
        })
      });
      showNotification('Message sent successfully', 'success');
      return message;
    } catch (error) {
      console.error('Send message error:', error);
      if (error.message.includes('not being sent to user with specified membership')) {
        showNotification('Failed to send message: Recipient membership number not found in the system', 'error');
      } else {
        showNotification('Failed to send message: ' + error.message, 'error');
      }
      throw error;
    }
  };
  
  const getMessages = async () => {
    const user = getCurrentUserSync();
    if (!user) throw new Error('User not logged in');
    try {
      const response = await apiRequest('/messages');
      const messages = response.data ? response.data.messages : response;
      const userMembership = user.data.user.membership_number || 'Admin';
      return messages.filter(m => 
        m.sender_membership === userMembership || m.recipient_membership === userMembership
      );
    } catch (error) {
      console.error('Get messages error:', error);
      showNotification('Failed to get messages: ' + error.message, 'error');
      throw error;
    }
  };
  
  const deleteMessage = async (messageId) => {
    if (!messageId) throw new Error('Message ID is required');
    try {
      await apiRequest(`/messages/${messageId}`, { method: 'DELETE' });
      showNotification('Message deleted successfully', 'success');
    } catch (error) {
      console.error('Delete message error:', error);
      showNotification('Failed to delete message: ' + error.message, 'error');
      throw error;
    }
  };
  
  // Admin API functions
  const isAdmin = u => u && u.data && u.data.user && u.data.user.role === 'admin';
  
  const getUsers = async () => {
    try {
      const response = await apiRequest('/users');
      return response.data ? response.data.users : response;
    } catch (error) {
      console.error('Get users error:', error);
      showNotification('Failed to get users: ' + error.message, 'error');
      throw error;
    }
  };
  
  const deleteUser = async (email) => {
    if (!email) throw new Error('Email is required');
    try {
      await apiRequest(`/admin/users/${encodeURIComponent(email)}`, { method: 'DELETE' });
      showNotification('User deleted successfully', 'success');
    } catch (error) {
      console.error('Delete user error:', error);
      showNotification('Failed to delete user: ' + error.message, 'error');
      throw error;
    }
  };
  
  const resetPassword = async (email, newPass) => {
    if (!email || !newPass) throw new Error('Email and password are required');
    try {
      await apiRequest('/admin/reset-password', {
        method: 'POST',
        body: JSON.stringify({ email, new_password: newPass })
      });
      showNotification('Password reset successfully', 'success');
    } catch (error) {
      console.error('Reset password error:', error);
      showNotification('Failed to reset password: ' + error.message, 'error');
      throw error;
    }
  };
  
  const getBanners = async () => {
    try {
      const response = await apiRequest('/admin/banners');
      return response.data || response;
    } catch (error) {
      console.error('Get banners error:', error);
      showNotification('Failed to get banners: ' + error.message, 'error');
      throw error;
    }
  };
  
  const updateBanners = async (banners) => {
    try {
      await apiRequest('/admin/banners', {
        method: 'PUT',
        body: JSON.stringify(banners)
      });
      showNotification('Banners updated successfully', 'success');
      return banners;
    } catch (error) {
      console.error('Update banners error:', error);
      showNotification('Failed to update banners: ' + error.message, 'error');
      throw error;
    }
  };
  
  const getAccessControl = async () => {
    try {
      const response = await apiRequest('/admin/access-control');
      return response.data || response;
    } catch (error) {
      console.error('Get access control error:', error);
      showNotification('Failed to get access control: ' + error.message, 'error');
      throw error;
    }
  };
  
  const updateAccessControl = async (acl) => {
    try {
      await apiRequest('/admin/access-control', {
        method: 'PUT',
        body: JSON.stringify(acl)
      });
      showNotification('Access control updated successfully', 'success');
      return acl;
    } catch (error) {
      console.error('Update access control error:', error);
      showNotification('Failed to update access control: ' + error.message, 'error');
      throw error;
    }
  };
  
  const updateUserAccess = async (userId, access) => {
    try {
      await apiRequest(`/admin/users/${userId}/access`, {
        method: 'PUT',
        body: JSON.stringify(access)
      });
      showNotification('User access updated successfully', 'success');
    } catch (error) {
      console.error('Update user access error:', error);
      showNotification('Failed to update user access: ' + error.message, 'error');
      throw error;
    }
  };
  
  const getUserAccess = async (userId) => {
    try {
      const response = await apiRequest(`/admin/users/${userId}/access`);
      return response.data || response;
    } catch (error) {
      console.error('Get user access error:', error);
      showNotification('Failed to get user access: ' + error.message, 'error');
      throw error;
    }
  };
  
  const canAccessPage = (user, pageId) => {
    if (!user) return false;
    if (isAdmin(user)) return true;
    
    // All pages except market and post-load are accessible by default
    if (pageId !== 'market' && pageId !== 'shipper-post') {
      return true;
    }
    
    const page = PAGES[pageId];
    if (page && page.roles.includes(user.data.user.role)) {
      return true;
    }
    return false;
  };
  
  const checkPageAccess = async (pageId) => {
    try {
      const user = getCurrentUserSync();
      if (!user) return false;
      if (canAccessPage(user, pageId)) return true;
      
      // For market and post-load pages, check user-specific access
      if (pageId === 'market' || pageId === 'shipper-post') {
        const userId = user.data.user.id;
        const userAccess = await getUserAccess(userId);
        if (userAccess && userAccess.pages && userAccess.pages[pageId]) {
          return userAccess.pages[pageId].enabled === true;
        }
      }
      
      return false;
    } catch (error) {
      console.error('Check page access error:', error);
      return false;
    }
  };
  
  // Get active banners for current page
  const getActiveBanners = async (page) => {
    try {
      const response = await apiRequest(`/banners/active?page=${page}`);
      return response.data || response;
    } catch (error) {
      console.error('Get active banners error:', error);
      return { banner: '' };
    }
  };
  
  // User Access Control Functions
  let currentSelectedUser = null;
  
  const populateUserDropdown = async () => {
    try {
      const users = await getUsers();
      const select = el('selectUserForAccess');
      if (!select) return;
      
      select.innerHTML = '<option value="">-- Select User --</option>';
      
      users.forEach(user => {
        const option = document.createElement('option');
        option.value = user.id;
        option.textContent = `${user.name} (${user.email}) - ${user.role}`;
        select.appendChild(option);
      });
    } catch (error) {
      console.error('Error populating user dropdown:', error);
    }
  };
  
  const loadUserAccess = async () => {
    const select = el('selectUserForAccess');
    if (!select) return;
    
    const userId = select.value;
    
    if (!userId) {
      showNotification('Please select a user first', 'warning');
      return;
    }
    
    try {
      const userAccess = await getUserAccess(userId);
      currentSelectedUser = userId;
      
      // Reset all toggles to unchecked first
      Object.values(ACCESS_PAGES).forEach(page => {
        const toggle = el(page.id);
        if (toggle) {
          toggle.checked = false;
        }
      });
      
      // Set toggles based on user access
      if (userAccess && userAccess.pages) {
        Object.entries(userAccess.pages).forEach(([pageId, access]) => {
          const page = ACCESS_PAGES[pageId];
          if (page && access.enabled) {
            const toggle = el(page.id);
            if (toggle) {
              toggle.checked = true;
            }
          }
        });
      }
      
      showNotification(`Loaded access for selected user`, 'success');
    } catch (error) {
      console.error('Error loading user access:', error);
      showNotification('Failed to load user access', 'error');
    }
  };
  
  const saveUserAccess = async () => {
    if (!currentSelectedUser) {
      showNotification('Please select and load a user first', 'warning');
      return;
    }
    
    const accessData = {
      pages: {}
    };
    
    // Collect all toggle states
    Object.entries(ACCESS_PAGES).forEach(([pageId, page]) => {
      const toggle = el(page.id);
      if (toggle) {
        accessData.pages[pageId] = {
          enabled: toggle.checked,
          name: page.name
        };
      }
    });
    
    try {
      await updateUserAccess(currentSelectedUser, accessData);
      showNotification('User access saved successfully', 'success');
    } catch (error) {
      console.error('Error saving user access:', error);
      showNotification('Failed to save user access', 'error');
    }
  };
  
  const refreshAccessControl = async () => {
    await populateUserDropdown();
    currentSelectedUser = null;
    
    // Reset all toggles
    Object.values(ACCESS_PAGES).forEach(page => {
      const toggle = el(page.id);
      if (toggle) {
        toggle.checked = false;
      }
    });
    
    showNotification('Access control refreshed', 'info');
  };
  
  // Load Management Functions for Admin
  const populateLoadDropdown = async () => {
    try {
      const loads = await getLoads();
      const select = el('selectLoad');
      if (!select) return;
      
      select.innerHTML = '<option value="">-- Select Load --</option>';
      
      loads.forEach(load => {
        const option = document.createElement('option');
        option.value = load.id;
        option.textContent = `${load.ref} - ${load.origin} to ${load.destination}`;
        select.appendChild(option);
      });
    } catch (error) {
      console.error('Error populating load dropdown:', error);
    }
  };
  
  const displayLoadDetails = async (loadId) => {
    try {
      const loads = await getLoads();
      const load = loads.find(l => l.id === loadId);
      
      if (!load) {
        showNotification('Load not found', 'error');
        return;
      }
      
      const loadDetails = el('loadDetails');
      const loadEditForm = el('loadEditForm');
      
      if (!loadDetails || !loadEditForm) return;
      
      // Clear previous content
      loadDetails.innerHTML = '';
      loadEditForm.innerHTML = '';
      
      // Create load details using createElement
      const detailsContainer = document.createElement('div');
      detailsContainer.className = 'load-details-content';
      
      const title = document.createElement('h4');
      title.textContent = 'Load Details';
      detailsContainer.appendChild(title);
      
      const detailRows = [
        { label: 'Reference', value: load.ref },
        { label: 'Origin', value: load.origin },
        { label: 'Destination', value: load.destination },
        { label: 'Pickup Date', value: new Date(load.date).toLocaleDateString() },
        { label: 'Expiry Date', value: new Date(load.expires_at).toLocaleDateString() },
        { label: 'Cargo Type', value: load.cargo_type },
        { label: 'Weight (Tons)', value: load.weight },
        { label: 'Status', value: getLoadStatus(load) },
        { label: 'Shipper', value: load.shipper_name || load.shipper_email },
        { label: 'Notes', value: load.notes || 'None' }
      ];
      
      detailRows.forEach(row => {
        const detailRow = document.createElement('div');
        detailRow.className = 'load-detail-row';
        
        const label = document.createElement('span');
        label.className = 'load-detail-label';
        label.textContent = row.label + ':';
        
        const value = document.createElement('span');
        value.className = 'load-detail-value';
        value.textContent = row.value;
        
        detailRow.appendChild(label);
        detailRow.appendChild(value);
        detailsContainer.appendChild(detailRow);
      });
      
      loadDetails.appendChild(detailsContainer);
      setHidden('loadDetails', false);
      
      // Create edit form
      const formContainer = document.createElement('div');
      formContainer.className = 'load-edit-form-content';
      
      const formTitle = document.createElement('h4');
      formTitle.textContent = 'Edit Load';
      formContainer.appendChild(formTitle);
      
      const editForm = document.createElement('form');
      editForm.id = 'formEditLoad';
      
      const formGrid = document.createElement('div');
      formGrid.className = 'grid two';
      
      const fields = [
        { id: 'editOrigin', label: 'Origin', value: load.origin, required: true },
        { id: 'editDestination', label: 'Destination', value: load.destination, required: true },
        { id: 'editDate', label: 'Pickup Date', value: load.date.split('T')[0], type: 'date', required: true },
        { id: 'editCargo', label: 'Cargo Type', value: load.cargo_type, required: true },
        { id: 'editWeight', label: 'Weight (Tons)', value: load.weight, type: 'number', required: true }
      ];
      
      fields.forEach(field => {
        const fieldContainer = document.createElement('div');
        
        const label = document.createElement('label');
        label.htmlFor = field.id;
        label.textContent = field.label;
        
        const input = document.createElement('input');
        input.id = field.id;
        input.name = field.id.replace('edit', '').toLowerCase();
        input.value = field.value;
        input.required = field.required;
        
        if (field.type) {
          input.type = field.type;
        }
        
        fieldContainer.appendChild(label);
        fieldContainer.appendChild(input);
        formGrid.appendChild(fieldContainer);
      });
      
      const notesContainer = document.createElement('div');
      notesContainer.className = 'grid-full-width';
      
      const notesLabel = document.createElement('label');
      notesLabel.htmlFor = 'editNotes';
      notesLabel.textContent = 'Notes';
      
      const notesTextarea = document.createElement('textarea');
      notesTextarea.id = 'editNotes';
      notesTextarea.name = 'notes';
      notesTextarea.rows = 3;
      notesTextarea.textContent = load.notes || '';
      
      notesContainer.appendChild(notesLabel);
      notesContainer.appendChild(notesTextarea);
      formGrid.appendChild(notesContainer);
      
      editForm.appendChild(formGrid);
      
      const formToolbar = document.createElement('div');
      formToolbar.className = 'toolbar toolbar-margin-top';
      
      const saveButton = document.createElement('button');
      saveButton.type = 'button';
      saveButton.className = 'btn primary';
      saveButton.textContent = 'Save Changes';
      saveButton.addEventListener('click', () => updateSelectedLoad(loadId));
      
      formToolbar.appendChild(saveButton);
      editForm.appendChild(formToolbar);
      
      formContainer.appendChild(editForm);
      loadEditForm.appendChild(formContainer);
      setHidden('loadEditForm', false);
      
    } catch (error) {
      console.error('Error displaying load details:', error);
      showNotification('Failed to load details', 'error');
    }
  };
  
  const updateSelectedLoad = async (loadId) => {
    try {
      const origin = el('editOrigin')?.value;
      const destination = el('editDestination')?.value;
      const date = el('editDate')?.value;
      const cargo = el('editCargo')?.value;
      const weight = el('editWeight')?.value;
      const notes = el('editNotes')?.value;
      
      if (!origin || !destination || !date || !cargo || !weight) {
        showNotification('Please fill in all required fields', 'error');
        return;
      }
      
      await updateLoad(loadId, {
        origin,
        destination,
        date,
        cargo_type: cargo,
        weight: parseFloat(weight),
        notes
      });
      
      showNotification('Load updated successfully', 'success');
      await populateLoadDropdown();
      setHidden('loadEditForm', true);
      
    } catch (error) {
      console.error('Error updating load:', error);
      showNotification('Failed to update load', 'error');
    }
  };
  
  const deleteSelectedLoad = async () => {
    const select = el('selectLoad');
    if (!select) return;
    
    const loadId = select.value;
    
    if (!loadId) {
      showNotification('Please select a load first', 'warning');
      return;
    }
    
    if (confirm('Are you sure you want to delete this load?')) {
      try {
        await deleteLoad(loadId);
        await populateLoadDropdown();
        setHidden('loadDetails', true);
        setHidden('loadEditForm', true);
        showNotification('Load deleted successfully', 'success');
      } catch (error) {
        console.error('Error deleting load:', error);
        showNotification('Failed to delete load', 'error');
      }
    }
  };
  
  // Render functions
  const renderShipper = async () => {
    const u = getCurrentUserSync();
    if (!u || u.data.user.role !== 'shipper') return;
    try {
      const loads = await getUserLoads();
      const tbody = el('tableMyLoadsShipper')?.querySelector('tbody');
      if (!tbody) return;
      
      // Clear table using safe method
      while (tbody.firstChild) {
        tbody.removeChild(tbody.firstChild);
      }
      
      if (!loads || loads.length === 0) {
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
        if (isLoadExpired(load)) row.classList.add('expired');
        
        const postedDate = new Date(load.created_at).toLocaleDateString();
        const expiryDate = new Date(load.expires_at).toLocaleDateString();
        const status = getLoadStatus(load);
        
        const refCell = document.createElement('td');
        refCell.textContent = sanitize(load.ref);
        
        const originCell = document.createElement('td');
        originCell.textContent = sanitize(load.origin);
        
        const destCell = document.createElement('td');
        destCell.textContent = sanitize(load.destination);
        
        const dateCell = document.createElement('td');
        dateCell.textContent = postedDate;
        
        const expiryCell = document.createElement('td');
        expiryCell.textContent = expiryDate;
        
        const cargoCell = document.createElement('td');
        cargoCell.textContent = sanitize(load.cargo_type);
        
        const weightCell = document.createElement('td');
        weightCell.textContent = load.weight;
        
        const statusCell = document.createElement('td');
        statusCell.innerHTML = getStatusBadge(status);
        
        const actionsCell = document.createElement('td');
        
        const editButton = document.createElement('button');
        editButton.className = 'btn';
        editButton.textContent = 'Edit';
        editButton.addEventListener('click', () => editUserLoad(load.id));
        
        const deleteButton = document.createElement('button');
        deleteButton.className = 'btn danger';
        deleteButton.textContent = 'Delete';
        deleteButton.addEventListener('click', () => deleteUserLoad(load.id));
        
        actionsCell.appendChild(editButton);
        actionsCell.appendChild(deleteButton);
        
        row.appendChild(refCell);
        row.appendChild(originCell);
        row.appendChild(destCell);
        row.appendChild(dateCell);
        row.appendChild(expiryCell);
        row.appendChild(cargoCell);
        row.appendChild(weightCell);
        row.appendChild(statusCell);
        row.appendChild(actionsCell);
        
        tbody.appendChild(row);
      });
    } catch (error) { console.error('Error rendering shipper dashboard:', error); }
  };
  
  const renderTransporter = async () => {
    const u = getCurrentUserSync();
    if (!u || u.data.user.role !== 'transporter') return;
    try {
      const loads = await getUserLoads();
      const tbody = el('tableMyLoadsTransporter')?.querySelector('tbody');
      if (!tbody) return;
      
      // Clear table using safe method
      while (tbody.firstChild) {
        tbody.removeChild(tbody.firstChild);
      }
      
      if (!loads || loads.length === 0) {
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
        if (isLoadExpired(load)) row.classList.add('expired');
        
        const postedDate = new Date(load.created_at).toLocaleDateString();
        const expiryDate = new Date(load.expires_at).toLocaleDateString();
        const status = getLoadStatus(load);
        
        const refCell = document.createElement('td');
        refCell.textContent = sanitize(load.ref);
        
        const originCell = document.createElement('td');
        originCell.textContent = sanitize(load.origin);
        
        const destCell = document.createElement('td');
        destCell.textContent = sanitize(load.destination);
        
        const dateCell = document.createElement('td');
        dateCell.textContent = postedDate;
        
        const expiryCell = document.createElement('td');
        expiryCell.textContent = expiryDate;
        
        const cargoCell = document.createElement('td');
        cargoCell.textContent = sanitize(load.cargo_type);
        
        const weightCell = document.createElement('td');
        weightCell.textContent = load.weight;
        
        const statusCell = document.createElement('td');
        statusCell.innerHTML = getStatusBadge(status);
        
        const actionsCell = document.createElement('td');
        
        const editButton = document.createElement('button');
        editButton.className = 'btn';
        editButton.textContent = 'Edit';
        editButton.addEventListener('click', () => editUserLoad(load.id));
        
        const deleteButton = document.createElement('button');
        deleteButton.className = 'btn danger';
        deleteButton.textContent = 'Delete';
        deleteButton.addEventListener('click', () => deleteUserLoad(load.id));
        
        actionsCell.appendChild(editButton);
        actionsCell.appendChild(deleteButton);
        
        row.appendChild(refCell);
        row.appendChild(originCell);
        row.appendChild(destCell);
        row.appendChild(dateCell);
        row.appendChild(expiryCell);
        row.appendChild(cargoCell);
        row.appendChild(weightCell);
        row.appendChild(statusCell);
        row.appendChild(actionsCell);
        
        tbody.appendChild(row);
      });
    } catch (error) { console.error('Error rendering transporter dashboard:', error); }
  };
  
  // Render market page to show membership numbers
  const renderMarket = async () => {
    try {
      const loads = await getLoads();
      const tbody = el('tableMarketLoads')?.querySelector('tbody');
      if (!tbody) return;
      
      // Clear table using safe method
      while (tbody.firstChild) {
        tbody.removeChild(tbody.firstChild);
      }
      
      if (!loads || loads.length === 0) {
        const row = document.createElement('tr');
        const cell = document.createElement('td');
        cell.colSpan = 10; // Changed to 10 columns
        cell.className = 'muted';
        cell.textContent = 'No loads available.';
        row.appendChild(cell);
        tbody.appendChild(row);
        return;
      }
      
      loads.forEach(load => {
        const row = document.createElement('tr');
        if (isLoadExpired(load)) row.classList.add('expired');
        
        const postedDate = new Date(load.created_at).toLocaleDateString();
        const expiryDate = new Date(load.expires_at).toLocaleDateString();
        const status = getLoadStatus(load);
        
        const refCell = document.createElement('td');
        refCell.textContent = sanitize(load.ref);
        
        const originCell = document.createElement('td');
        originCell.textContent = sanitize(load.origin);
        
        const destCell = document.createElement('td');
        destCell.textContent = sanitize(load.destination);
        
        const dateCell = document.createElement('td');
        dateCell.textContent = postedDate;
        
        const expiryCell = document.createElement('td');
        expiryCell.textContent = expiryDate;
        
        const cargoCell = document.createElement('td');
        cargoCell.textContent = sanitize(load.cargo_type);
        
        const weightCell = document.createElement('td');
        weightCell.textContent = load.weight;
        
        const statusCell = document.createElement('td');
        statusCell.innerHTML = getStatusBadge(status);
        
        // Show membership number instead of name/email
        const postedByCell = document.createElement('td');
        postedByCell.textContent = sanitize(load.shipper_membership || load.posted_by || 'Unknown');
        
        const actionsCell = document.createElement('td');
        const contactButton = document.createElement('button');
        contactButton.className = 'btn';
        contactButton.textContent = 'Contact';
        contactButton.addEventListener('click', () => {
          const membershipNumber = load.shipper_membership || load.posted_by;
          if (membershipNumber) {
            location.hash = '#messages';
            // Use proper timeout
            const timeoutId = setTimeout(() => {
              const msgTo = el('msgTo');
              if (msgTo) msgTo.value = membershipNumber;
            }, 100);
            // Store timeout ID for potential cleanup
            contactButton.dataset.timeoutId = timeoutId;
          }
        });
        actionsCell.appendChild(contactButton);
        
        row.appendChild(refCell);
        row.appendChild(originCell);
        row.appendChild(destCell);
        row.appendChild(dateCell);
        row.appendChild(expiryCell);
        row.appendChild(cargoCell);
        row.appendChild(weightCell);
        row.appendChild(statusCell);
        row.appendChild(postedByCell);
        row.appendChild(actionsCell);
        
        tbody.appendChild(row);
      });
    } catch (error) { console.error('Error rendering market:', error); }
  };
  
  const renderMessages = async () => {
    try {
      const messages = await getMessages();
      const messageContainer = el('messageContainer');
      if (!messageContainer) return;
      
      // Clear container using safe method
      while (messageContainer.firstChild) {
        messageContainer.removeChild(messageContainer.firstChild);
      }
      
      if (!messages || messages.length === 0) {
        const noMessages = document.createElement('div');
        noMessages.className = 'muted';
        noMessages.textContent = 'No messages.';
        messageContainer.appendChild(noMessages);
        return;
      }
      
      // Sort messages by date (newest first)
      messages.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
      
      messages.forEach(msg => {
        const messageDiv = document.createElement('div');
        const user = getCurrentUserSync();
        const userMembership = user.data.user.membership_number || 'Admin';
        
        if (msg.sender_membership === userMembership) {
          messageDiv.className = 'message message-sent';
        } else {
          messageDiv.className = 'message message-received';
        }
        
        const messageHeader = document.createElement('div');
        messageHeader.className = 'message-header';
        
        const sender = document.createElement('div');
        sender.className = 'message-sender';
        sender.textContent = msg.sender_membership === 'Admin' ? 'Admin' : `From: ${msg.sender_membership}`;
        
        const time = document.createElement('div');
        time.className = 'message-time';
        time.textContent = new Date(msg.created_at).toLocaleString();
        
        messageHeader.appendChild(sender);
        messageHeader.appendChild(time);
        
        const messageBody = document.createElement('div');
        messageBody.className = 'message-body';
        messageBody.textContent = msg.body;
        
        messageDiv.appendChild(messageHeader);
        messageDiv.appendChild(messageBody);
        messageContainer.appendChild(messageDiv);
      });
    } catch (error) { console.error('Error rendering messages:', error); }
  };
  
  // Render banners based on page context
  const renderBanners = async () => {
    const hash = location.hash.slice(1) || 'index';
    
    // Only show banners on index and dashboard pages
    if (hash === 'index' || hash.includes('dashboard')) {
      try {
        const banners = await getActiveBanners(hash);
        const indexBanner = el('indexBanner');
        const dashBannerShipper = el('dashBannerShipper');
        const dashBannerTransporter = el('dashBannerTransporter');
        
        if (hash === 'index' && indexBanner && banners.banner) {
          indexBanner.textContent = banners.banner;
          indexBanner.classList.remove('hidden');
        } else if (indexBanner) {
          indexBanner.classList.add('hidden');
        }
        
        if (hash === 'shipper-dashboard' && dashBannerShipper && banners.banner) {
          dashBannerShipper.textContent = banners.banner;
          dashBannerShipper.classList.remove('hidden');
        } else if (dashBannerShipper) {
          dashBannerShipper.classList.add('hidden');
        }
        
        if (hash === 'transporter-dashboard' && dashBannerTransporter && banners.banner) {
          dashBannerTransporter.textContent = banners.banner;
          dashBannerTransporter.classList.remove('hidden');
        } else if (dashBannerTransporter) {
          dashBannerTransporter.classList.add('hidden');
        }
      } catch (error) {
        console.error('Error rendering banners:', error);
      }
    } else {
      // Hide all banners on other pages
      const indexBanner = el('indexBanner');
      const dashBannerShipper = el('dashBannerShipper');
      const dashBannerTransporter = el('dashBannerTransporter');
      const marketBanner = el('marketBanner');
      
      if (indexBanner) indexBanner.classList.add('hidden');
      if (dashBannerShipper) dashBannerShipper.classList.add('hidden');
      if (dashBannerTransporter) dashBannerTransporter.classList.add('hidden');
      if (marketBanner) marketBanner.classList.add('hidden');
    }
  };
  
  // Profile rendering with membership date
  const renderShipperProfile = async () => {
    const u = getCurrentUserSync();
    if (!u || u.data.user.role !== 'shipper') return;
    try {
      const user = u.data.user;
      setText('shipperProfileName', user.name);
      setText('shipperProfileEmail', user.email);
      setText('shipperProfileCompany', user.company || 'Not specified');
      setText('shipperProfilePhone', user.phone || 'Not specified');
      setText('shipperProfileAddress', user.address || 'Not specified');
      setText('shipperProfileRole', user.role);
      
      // Use membership_date or created_at
      const joinDate = user.membership_date || user.created_at;
      setText('shipperProfileCreated', new Date(joinDate).toLocaleDateString());
      setText('shipperProfileSince', new Date(joinDate).toLocaleDateString());
      
      // Display membership number
      const membershipNumber = user.membership_number || 'Not assigned';
      setText('shipperProfileMembership', membershipNumber);
      
      const avatar = el('shipperProfileAvatar');
      if (avatar) avatar.textContent = user.name.charAt(0).toUpperCase();
      
      // Populate form fields
      const nameField = el('profileShipperName');
      const phoneField = el('profileShipperPhone');
      const addressField = el('profileShipperAddress');
      if (nameField) nameField.value = user.name || '';
      if (phoneField) phoneField.value = user.phone || '';
      if (addressField) addressField.value = user.address || '';
      
    } catch (error) { console.error('Error rendering shipper profile:', error); }
  };
  
  // Similar updates for transporter profile
  const renderTransporterProfile = async () => {
    const u = getCurrentUserSync();
    if (!u || u.data.user.role !== 'transporter') return;
    try {
      const user = u.data.user;
      setText('transporterProfileName', user.name);
      setText('transporterProfileEmail', user.email);
      setText('transporterProfileCompany', user.company || 'Not specified');
      setText('transporterProfileVehicle', user.vehicle_info || 'Not specified');
      setText('transporterProfilePhone', user.phone || 'Not specified');
      setText('transporterProfileAddress', user.address || 'Not specified');
      setText('transporterProfileRole', user.role);
      
      // Use membership_date or created_at
      const joinDate = user.membership_date || user.created_at;
      setText('transporterProfileCreated', new Date(joinDate).toLocaleDateString());
      setText('transporterProfileSince', new Date(joinDate).toLocaleDateString());
      
      // Display membership number
      const membershipNumber = user.membership_number || 'Not assigned';
      setText('transporterProfileMembership', membershipNumber);
      
      const avatar = el('transporterProfileAvatar');
      if (avatar) avatar.textContent = user.name.charAt(0).toUpperCase();
      
      // Populate form fields
      const nameField = el('profileTransporterName');
      const phoneField = el('profileTransporterPhone');
      const addressField = el('profileTransporterAddress');
      if (nameField) nameField.value = user.name || '';
      if (phoneField) phoneField.value = user.phone || '';
      if (addressField) addressField.value = user.address || '';
      
    } catch (error) { console.error('Error rendering transporter profile:', error); }
  };
  
  // Admin navigation - show all pages for admin
  const renderHeader = async () => {
    const u = getCurrentUserSync();
    const navLinks = el('navLinks');
    const authUser = el('authUser');
    const btnLoginNav = el('btnLoginNav');
    const btnLogout = el('btnLogout');
    const roleChip = el('roleChip');
    
    if (u && u.data && u.data.user) {
      // Clear navLinks using safe method
      if (navLinks) {
        while (navLinks.firstChild) {
          navLinks.removeChild(navLinks.firstChild);
        }
      }
      
      if (authUser) authUser.textContent = u.data.user.name;
      if (btnLoginNav) btnLoginNav.classList.add('hidden');
      if (btnLogout) btnLogout.classList.remove('hidden');
      if (roleChip) {
        roleChip.textContent = u.data.user.role;
        roleChip.classList.remove('hidden');
      }
      
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
          // Admin can see navigation to all pages
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
      // Clear navLinks using safe method
      if (navLinks) {
        while (navLinks.firstChild) {
          navLinks.removeChild(navLinks.firstChild);
        }
      }
      
      if (authUser) authUser.textContent = '';
      if (btnLoginNav) btnLoginNav.classList.remove('hidden');
      if (btnLogout) btnLogout.classList.add('hidden');
      if (roleChip) roleChip.classList.add('hidden');
    }
  };
  
  const renderAccessWarnings = async () => {
    const u = getCurrentUserSync();
    if (!u) return;
    
    const shipperWarning = el('accessWarningShipper');
    const transporterWarning = el('accessWarningTransporter');
    
    // Reset warnings
    if (shipperWarning) {
      shipperWarning.classList.add('hidden');
      shipperWarning.textContent = '';
    }
    if (transporterWarning) {
      transporterWarning.classList.add('hidden');
      transporterWarning.textContent = '';
    }
    
    // Check access to post load and market pages
    const hasPostLoadAccess = await checkPageAccess('shipper-post');
    const hasMarketAccess = await checkPageAccess('market');
    
    if (u.data.user.role === 'shipper') {
      if (!hasPostLoadAccess || !hasMarketAccess) {
        let warningText = '';
        if (!hasPostLoadAccess && !hasMarketAccess) {
          warningText = 'You do not have access to Post Load and Market pages. Please contact admin via Messages page.';
        } else if (!hasPostLoadAccess) {
          warningText = 'You do not have access to Post Load page. Please contact admin via Messages page.';
        } else if (!hasMarketAccess) {
          warningText = 'You do not have access to Market page. Please contact admin via Messages page.';
        }
        
        if (shipperWarning) {
          shipperWarning.textContent = warningText;
          shipperWarning.classList.remove('hidden');
        }
      }
    } else if (u.data.user.role === 'transporter') {
      if (!hasPostLoadAccess || !hasMarketAccess) {
        let warningText = '';
        if (!hasPostLoadAccess && !hasMarketAccess) {
          warningText = 'You do not have access to Post Load and Market pages. Please contact admin via Messages page.';
        } else if (!hasPostLoadAccess) {
          warningText = 'You do not have access to Post Load page. Please contact admin via Messages page.';
        } else if (!hasMarketAccess) {
          warningText = 'You do not have access to Market page. Please contact admin via Messages page.';
        }
        
        if (transporterWarning) {
          transporterWarning.textContent = warningText;
          transporterWarning.classList.remove('hidden');
        }
      }
    }
  };
  
  const renderControl = async () => {
    const u = getCurrentUserSync();
    if (!isAdmin(u)) return;
    
    try {
      const users = await getUsers();
      const tbodyUsers = el('tableUsers')?.querySelector('tbody');
      if (!tbodyUsers) return;
      
      // Clear table using safe method
      while (tbodyUsers.firstChild) {
        tbodyUsers.removeChild(tbodyUsers.firstChild);
      }
      
      users.forEach(user => {
        const row = document.createElement('tr');
        
        const nameCell = document.createElement('td');
        nameCell.textContent = user.name;
        
        const emailCell = document.createElement('td');
        emailCell.textContent = user.email;
        
        const membershipCell = document.createElement('td');
        const membershipSpan = document.createElement('span');
        membershipSpan.className = 'membership-number';
        membershipSpan.textContent = user.membership_number || 'Not assigned';
        membershipCell.appendChild(membershipSpan);
        
        const roleCell = document.createElement('td');
        roleCell.textContent = user.role;
        
        const joinDateCell = document.createElement('td');
        joinDateCell.textContent = new Date(user.created_at).toLocaleDateString();
        
        const actionsCell = document.createElement('td');
        const deleteButton = document.createElement('button');
        deleteButton.className = 'btn danger';
        deleteButton.textContent = 'Delete';
        deleteButton.addEventListener('click', () => deleteUser(user.email));
        actionsCell.appendChild(deleteButton);
        
        row.appendChild(nameCell);
        row.appendChild(emailCell);
        row.appendChild(membershipCell);
        row.appendChild(roleCell);
        row.appendChild(joinDateCell);
        row.appendChild(actionsCell);
        
        tbodyUsers.appendChild(row);
      });
      
      // Populate user dropdowns
      await populateUserDropdown();
      await populateLoadDropdown();
      
      const selectUserForPassword = el('selectUserForPassword');
      if (selectUserForPassword) {
        // Clear dropdown using safe method
        while (selectUserForPassword.firstChild) {
          selectUserForPassword.removeChild(selectUserForPassword.firstChild);
        }
        
        const defaultOption = document.createElement('option');
        defaultOption.value = '';
        defaultOption.textContent = '-- Select User --';
        selectUserForPassword.appendChild(defaultOption);
        
        users.forEach(user => {
          const option = document.createElement('option');
          option.value = user.email;
          option.textContent = `${user.name} (${user.email})`;
          selectUserForPassword.appendChild(option);
        });
      }
      
    } catch (error) { console.error('Error rendering control:', error); }
  };
  
  // Main render function to include banner updates
  const render = async () => {
    await renderHeader();
    await renderBanners(); // Call after header
    await renderAccessWarnings();
    
    // Hide all pages first
    document.querySelectorAll('section').forEach(s => s.classList.add('hidden'));
    
    const hash = location.hash.slice(1) || 'index';
    const u = getCurrentUserSync();
    
    // Check if user can access the requested page
    let canAccess = false;
    if (hash === 'index' || hash === 'login' || hash === 'register-options' || 
        hash === 'register-shipper' || hash === 'register-transporter') {
      canAccess = true;
    } else if (u) {
      canAccess = await checkPageAccess(hash);
    }
    
    if (!canAccess) {
      if (u) {
        location.hash = u.data.user.role === 'admin' ? '#control' : 
                       u.data.user.role === 'shipper' ? '#shipper-dashboard' : '#transporter-dashboard';
      } else {
        location.hash = '#login';
      }
      return;
    }
    
    // Show the appropriate page
    setHidden(`page-${hash}`, false);
    
    // Render page-specific content
    switch(hash) {
      case 'shipper-dashboard':
        await renderShipper();
        break;
      case 'transporter-dashboard':
        await renderTransporter();
        break;
      case 'market':
        await renderMarket(); // Uses new market rendering
        break;
      case 'messages':
        await renderMessages();
        break;
      case 'shipper-profile':
        await renderShipperProfile(); // Uses new profile rendering
        break;
      case 'transporter-profile':
        await renderTransporterProfile(); // Uses new profile rendering
        break;
      case 'control':
        await renderControl();
        break;
    }
  };
  
  // User load management functions
  const editUserLoad = async (loadId) => {
    try {
      const loads = await getLoads();
      const load = loads.find(l => l.id === loadId);
      
      if (!load) {
        showNotification('Load not found', 'error');
        return;
      }
      
      // Create a simple edit form in a modal-like approach
      const editForm = document.createElement('div');
      editForm.className = 'modal-overlay';
      
      const formContent = document.createElement('div');
      formContent.className = 'card modal-content';
      
      const formTitle = document.createElement('h3');
      formTitle.textContent = 'Edit Load';
      formContent.appendChild(formTitle);
      
      const form = document.createElement('form');
      form.id = 'formEditUserLoad';
      
      const formGrid = document.createElement('div');
      formGrid.className = 'grid two';
      
      const fields = [
        { id: 'userEditOrigin', label: 'Origin', value: load.origin, required: true },
        { id: 'userEditDestination', label: 'Destination', value: load.destination, required: true },
        { id: 'userEditDate', label: 'Pickup Date', value: load.date.split('T')[0], type: 'date', required: true },
        { id: 'userEditCargo', label: 'Cargo Type', value: load.cargo_type, required: true },
        { id: 'userEditWeight', label: 'Weight (Tons)', value: load.weight, type: 'number', required: true }
      ];
      
      fields.forEach(field => {
        const fieldContainer = document.createElement('div');
        
        const label = document.createElement('label');
        label.htmlFor = field.id;
        label.textContent = field.label;
        
        const input = document.createElement('input');
        input.id = field.id;
        input.name = field.id.replace('userEdit', '').toLowerCase();
        input.value = field.value;
        input.required = field.required;
        
        if (field.type) {
          input.type = field.type;
        }
        
        fieldContainer.appendChild(label);
        fieldContainer.appendChild(input);
        formGrid.appendChild(fieldContainer);
      });
      
      const notesContainer = document.createElement('div');
      notesContainer.className = 'grid-full-width';
      
      const notesLabel = document.createElement('label');
      notesLabel.htmlFor = 'userEditNotes';
      notesLabel.textContent = 'Notes';
      
      const notesTextarea = document.createElement('textarea');
      notesTextarea.id = 'userEditNotes';
      notesTextarea.name = 'notes';
      notesTextarea.rows = 3;
      notesTextarea.textContent = load.notes || '';
      
      notesContainer.appendChild(notesLabel);
      notesContainer.appendChild(notesTextarea);
      formGrid.appendChild(notesContainer);
      
      form.appendChild(formGrid);
      
      const formToolbar = document.createElement('div');
      formToolbar.className = 'toolbar toolbar-margin-top';
      
      const saveButton = document.createElement('button');
      saveButton.type = 'button';
      saveButton.className = 'btn primary';
      saveButton.textContent = 'Save Changes';
      saveButton.addEventListener('click', async () => {
        const origin = el('userEditOrigin')?.value;
        const destination = el('userEditDestination')?.value;
        const date = el('userEditDate')?.value;
        const cargo = el('userEditCargo')?.value;
        const weight = el('userEditWeight')?.value;
        const notes = el('userEditNotes')?.value;
        
        if (!origin || !destination || !date || !cargo || !weight) {
          showNotification('Please fill in all required fields', 'error');
          return;
        }
        
        try {
          await updateLoad(loadId, {
            origin,
            destination,
            date,
            cargo_type: cargo,
            weight: parseFloat(weight),
            notes
          });
          
          showNotification('Load updated successfully', 'success');
          document.body.removeChild(editForm);
          await render();
        } catch (error) {
          console.error('Error updating load:', error);
          showNotification('Failed to update load', 'error');
        }
      });
      
      const cancelButton = document.createElement('button');
      cancelButton.type = 'button';
      cancelButton.className = 'btn';
      cancelButton.textContent = 'Cancel';
      cancelButton.addEventListener('click', () => document.body.removeChild(editForm));
      
      formToolbar.appendChild(saveButton);
      formToolbar.appendChild(cancelButton);
      form.appendChild(formToolbar);
      
      formContent.appendChild(form);
      editForm.appendChild(formContent);
      document.body.appendChild(editForm);
      
    } catch (error) {
      console.error('Error editing load:', error);
      showNotification('Failed to edit load', 'error');
    }
  };
  
  const deleteUserLoad = async (loadId) => {
    if (confirm('Are you sure you want to delete this load?')) {
      try {
        await deleteLoad(loadId);
        showNotification('Load deleted successfully', 'success');
        await render();
      } catch (error) {
        console.error('Error deleting load:', error);
        showNotification('Failed to delete load', 'error');
      }
    }
  };
  
  // Profile save handlers
  const initProfileSaveHandlers = () => {
    // Shipper profile save
    const saveShipperBtn = el('saveProfileShipper');
    if (saveShipperBtn) {
      saveShipperBtn.addEventListener('click', async () => {
        const name = el('profileShipperName')?.value;
        const phone = el('profileShipperPhone')?.value;
        const address = el('profileShipperAddress')?.value;
        const password = el('profileShipperPassword')?.value;
        
        if (!name || !phone) {
          showNotification('Name and phone are required', 'error');
          return;
        }
        
        setButtonLoading('saveProfileShipper', true);
        try {
          const profileData = { name, phone, address };
          if (password) {
            profileData.password = password;
          }
          await updateUserProfile(profileData);
          showNotification('Profile updated successfully', 'success');
          location.hash = '#shipper-dashboard';
        } catch (error) {
          console.error('Error updating profile:', error);
        } finally {
          setButtonLoading('saveProfileShipper', false);
        }
      });
    }
    
    // Transporter profile save
    const saveTransporterBtn = el('saveProfileTransporter');
    if (saveTransporterBtn) {
      saveTransporterBtn.addEventListener('click', async () => {
        const name = el('profileTransporterName')?.value;
        const phone = el('profileTransporterPhone')?.value;
        const address = el('profileTransporterAddress')?.value;
        const password = el('profileTransporterPassword')?.value;
        
        if (!name || !phone) {
          showNotification('Name and phone are required', 'error');
          return;
        }
        
        setButtonLoading('saveProfileTransporter', true);
        try {
          const profileData = { name, phone, address };
          if (password) {
            profileData.password = password;
          }
          await updateUserProfile(profileData);
          showNotification('Profile updated successfully', 'success');
          location.hash = '#transporter-dashboard';
        } catch (error) {
          console.error('Error updating profile:', error);
        } finally {
          setButtonLoading('saveProfileTransporter', false);
        }
      });
    }
  };
  
  // Event handlers
  const init = () => {
    // Form submissions
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
        setButtonLoading('formLogin', true);
        try {
          const user = await login(email, password);
          if (user) {
            location.hash = user.data.user.role === 'admin' ? '#control' : 
                           user.data.user.role === 'shipper' ? '#shipper-dashboard' : '#transporter-dashboard';
          }
        } catch (error) {
          console.error('Login error:', error);
        } finally {
          setButtonLoading('formLogin', false);
        }
      });
    }
    
    const regShipperForm = el('formRegShipper');
    if (regShipperForm) {
      regShipperForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const data = Object.fromEntries(formData);
        data.role = 'shipper';
        setButtonLoading('formRegShipper', true);
        try {
          await registerUser(data);
          location.hash = '#shipper-dashboard';
        } catch (error) {
          console.error('Registration error:', error);
        } finally {
          setButtonLoading('formRegShipper', false);
        }
      });
    }
    
    const regTransporterForm = el('formRegTransporter');
    if (regTransporterForm) {
      regTransporterForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const data = Object.fromEntries(formData);
        data.role = 'transporter';
        setButtonLoading('formRegTransporter', true);
        try {
          await registerUser(data);
          location.hash = '#transporter-dashboard';
        } catch (error) {
          console.error('Registration error:', error);
        } finally {
          setButtonLoading('formRegTransporter', false);
        }
      });
    }
    
    // Post load form - removed shipper ID and email fields
    const postLoadForm = el('formPostLoad');
    if (postLoadForm) {
      postLoadForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const data = Object.fromEntries(formData);
        setButtonLoading('formPostLoad', true);
        try {
          await postLoad(data);
          e.target.reset();
          location.hash = getCurrentUserSync()?.data?.user?.role === 'shipper' ? '#shipper-dashboard' : '#transporter-dashboard';
        } catch (error) {
          console.error('Post load error:', error);
        } finally {
          setButtonLoading('formPostLoad', false);
        }
      });
    }
    
    const sendMsgForm = el('formSendMsg');
    if (sendMsgForm) {
      sendMsgForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const to = el('msgTo')?.value;
        const body = el('msgBody')?.value;
        setButtonLoading('formSendMsg', true);
        try {
          await sendMessage(to, body);
          e.target.reset();
          await renderMessages();
        } catch (error) {
          console.error('Send message error:', error);
        } finally {
          setButtonLoading('formSendMsg', false);
        }
      });
    }
    
    // Access control event listeners
    const loadAccessBtn = el('btnLoadUserAccess');
    if (loadAccessBtn) loadAccessBtn.addEventListener('click', loadUserAccess);
    
    const saveAccessBtn = el('btnSaveUserAccess');
    if (saveAccessBtn) saveAccessBtn.addEventListener('click', saveUserAccess);
    
    const refreshAccessBtn = el('btnRefreshAccessControl');
    if (refreshAccessBtn) refreshAccessBtn.addEventListener('click', refreshAccessControl);
    
    // Load management event listeners
    const loadDetailsBtn = el('btnLoadLoadDetails');
    if (loadDetailsBtn) {
      loadDetailsBtn.addEventListener('click', async () => {
        const select = el('selectLoad');
        if (!select) return;
        
        const loadId = select.value;
        
        if (!loadId) {
          showNotification('Please select a load first', 'warning');
          return;
        }
        
        await displayLoadDetails(loadId);
      });
    }
    
    const deleteLoadBtn = el('btnDeleteLoad');
    if (deleteLoadBtn) deleteLoadBtn.addEventListener('click', deleteSelectedLoad);
    
    // Reset password functionality
    const resetPassBtn = el('btnResetPass');
    if (resetPassBtn) {
      resetPassBtn.addEventListener('click', async () => {
        const select = el('selectUserForPassword');
        const password = el('resetPass')?.value;
        const email = select?.value;
        
        if (!email || !password) {
          showNotification('Please select a user and enter a new password', 'warning');
          return;
        }
        
        try {
          await resetPassword(email, password);
          showNotification('Password reset successfully', 'success');
          const resetPassField = el('resetPass');
          if (resetPassField) resetPassField.value = '';
        } catch (error) {
          console.error('Reset password error:', error);
          showNotification('Failed to reset password: ' + error.message, 'error');
        }
      });
    }
    
    const logoutBtn = el('btnLogout');
    if (logoutBtn) logoutBtn.addEventListener('click', logout);
    
    const marketFilterBtn = el('btnMarketFilterLoads');
    if (marketFilterBtn) {
      marketFilterBtn.addEventListener('click', async () => {
        const origin = el('marketFilterOrigin')?.value;
        const destination = el('marketFilterDest')?.value;
        try {
          const loads = await getLoads({ origin, destination });
          const tbody = el('tableMarketLoads')?.querySelector('tbody');
          if (!tbody) return;
          
          // Clear table using safe method
          while (tbody.firstChild) {
            tbody.removeChild(tbody.firstChild);
          }
          
          if (!loads || loads.length === 0) {
            const row = document.createElement('tr');
            const cell = document.createElement('td');
            cell.colSpan = 10;
            cell.className = 'muted';
            cell.textContent = 'No loads found matching your criteria.';
            row.appendChild(cell);
            tbody.appendChild(row);
            return;
          }
          
          loads.forEach(load => {
            const row = document.createElement('tr');
            if (isLoadExpired(load)) row.classList.add('expired');
            
            const postedDate = new Date(load.created_at).toLocaleDateString();
            const expiryDate = new Date(load.expires_at).toLocaleDateString();
            const status = getLoadStatus(load);
            
            const refCell = document.createElement('td');
            refCell.textContent = sanitize(load.ref);
            
            const originCell = document.createElement('td');
            originCell.textContent = sanitize(load.origin);
            
            const destCell = document.createElement('td');
            destCell.textContent = sanitize(load.destination);
            
            const dateCell = document.createElement('td');
            dateCell.textContent = postedDate;
            
            const expiryCell = document.createElement('td');
            expiryCell.textContent = expiryDate;
            
            const cargoCell = document.createElement('td');
            cargoCell.textContent = sanitize(load.cargo_type);
            
            const weightCell = document.createElement('td');
            weightCell.textContent = load.weight;
            
            const statusCell = document.createElement('td');
            statusCell.innerHTML = getStatusBadge(status);
            
            // Show membership number instead of name/email
            const postedByCell = document.createElement('td');
            postedByCell.textContent = sanitize(load.shipper_membership || load.posted_by || 'Unknown');
            
            const actionsCell = document.createElement('td');
            const contactButton = document.createElement('button');
            contactButton.className = 'btn';
            contactButton.textContent = 'Contact';
            contactButton.addEventListener('click', () => {
              const membershipNumber = load.shipper_membership || load.posted_by;
              if (membershipNumber) {
                location.hash = '#messages';
                // Use proper timeout
                const timeoutId = setTimeout(() => {
                  const msgTo = el('msgTo');
                  if (msgTo) msgTo.value = membershipNumber;
                }, 100);
                // Store timeout ID for potential cleanup
                contactButton.dataset.timeoutId = timeoutId;
              }
            });
            actionsCell.appendChild(contactButton);
            
            row.appendChild(refCell);
            row.appendChild(originCell);
            row.appendChild(destCell);
            row.appendChild(dateCell);
            row.appendChild(expiryCell);
            row.appendChild(cargoCell);
            row.appendChild(weightCell);
            row.appendChild(statusCell);
            row.appendChild(postedByCell);
            row.appendChild(actionsCell);
            
            tbody.appendChild(row);
          });
        } catch (error) { console.error('Error filtering loads:', error); }
      });
    }
    
    // Initialize profile save handlers
    initProfileSaveHandlers();
    
    // Global functions for onclick handlers
    window.deleteUser = async (email) => {
      if (confirm('Are you sure you want to delete this user?')) {
        try {
          await deleteUser(email);
          await render();
        } catch (error) {
          console.error('Error deleting user:', error);
        }
      }
    };
    
    window.deleteMessage = async (messageId) => {
      if (confirm('Are you sure you want to delete this message?')) {
        try {
          await deleteMessage(messageId);
          await renderMessages();
        } catch (error) {
          console.error('Error deleting message:', error);
        }
      }
    };
    
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
