// app.js - MakiwaFreight Production Frontend
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
    return str.toString()
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  };
  
  // Validate email format
  const isValidEmail = email => {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
  };

  // Validate membership number format
  const isValidMembership = membership => {
    return /^MF\d{6}$/.test(membership);
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
    
    const container = el('notificationContainer');
    if (container) {
      container.appendChild(notification);
      
      requestAnimationFrame(() => {
        notification.classList.add('show');
      });
      
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
    const activityEvents = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'];
    activityEvents.forEach(event => {
      document.addEventListener(event, resetSessionTimer, false);
    });
    
    el('extendSession')?.addEventListener('click', extendSession);
    el('logoutSession')?.addEventListener('click', logout);
    
    resetSessionTimer();
  };
  
  // API helper functions
  const apiRequest = async (endpoint, options = {}) => {
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers
    };
    
    const user = getCurrentUserSync();
    if (user && user.token) {
      headers['Authorization'] = `Bearer ${user.token}`;
    }
    
    try {
      const response = await fetch(`${API_BASE}${endpoint}`, {
        ...options,
        headers
      });
      
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
        
        const timeoutId = setTimeout(() => {
          warning.classList.add('hidden');
        }, 10000);
        warning.dataset.timeoutId = timeoutId;
      }
    });
  };
  
  // Get current user synchronously
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

  // Check if user is admin
  const isAdmin = user => user && user.role === 'admin';
  
  // Authentication API functions
  const login = async (email, password) => {
    if (!email || !password) return null;
    email = email.trim().toLowerCase();
    try {
      const response = await apiRequest('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password })
      });
      
      if (response) {
        const userData = {
          ...response,
          token: 'auth-token-' + Date.now() // Simple token for demo
        };
        sessionStorage.setItem('currentUser', JSON.stringify(userData));
        showNotification('Login successful', 'success');
        setupSessionTimeout();
        return userData;
      }
      return null;
    } catch (error) {
      console.error('Login error:', error);
      showNotification('Login failed: ' + error.message, 'error');
      return null;
    }
  };
  
  const logout = () => {
    clearTimeout(sessionTimeout);
    clearTimeout(sessionWarningTimeout);
    
    document.querySelectorAll('.notification').forEach(notification => {
      if (notification.dataset.timeoutId) {
        clearTimeout(parseInt(notification.dataset.timeoutId));
      }
      if (notification.dataset.removeTimeoutId) {
        clearTimeout(parseInt(notification.dataset.removeTimeoutId));
      }
    });
    
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

      // Generate membership number for display
      const membershipNumber = 'MF' + Date.now().toString().slice(-6);
      
      if (sanitizedData.role === 'shipper') {
        const shipperMembershipEl = el('shipperMembershipNumber');
        if (shipperMembershipEl) {
          shipperMembershipEl.textContent = `Your Membership Number: ${membershipNumber}`;
          shipperMembershipEl.classList.remove('display-none');
        }
      } else if (sanitizedData.role === 'transporter') {
        const transporterMembershipEl = el('transporterMembershipNumber');
        if (transporterMembershipEl) {
          transporterMembershipEl.textContent = `Your Membership Number: ${membershipNumber}`;
          transporterMembershipEl.classList.remove('display-none');
        }
      }

      showNotification(`Registration successful! Your membership number is ${membershipNumber}`, 'success');

      // Auto login after registration
      if (response) {
        const userData = {
          ...response,
          token: 'auth-token-' + Date.now(),
          membership_number: membershipNumber
        };
        sessionStorage.setItem('currentUser', JSON.stringify(userData));
        setupSessionTimeout();
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
    
    const user = getCurrentUserSync();
    if (!user || !user.id) throw new Error('User not found');

    const sanitizedData = {};
    for (const key in profileData) {
      if (['name', 'phone', 'address', 'password', 'company', 'vehicle_info'].includes(key)) {
        sanitizedData[key] = profileData[key];
      }
    }

    try {
      const response = await apiRequest(`/users/${user.id}`, {
        method: 'PUT',
        body: JSON.stringify(sanitizedData)
      });
      
      // Update current user in session
      const currentUser = getCurrentUserSync();
      if (currentUser) {
        const updatedUser = { ...currentUser, ...response };
        sessionStorage.setItem('currentUser', JSON.stringify(updatedUser));
      }
      
      showNotification('Profile updated successfully', 'success');
      return response;
    } catch (error) {
      console.error('Profile update error:', error);
      showNotification('Profile update failed: ' + error.message, 'error');
      throw error;
    }
  };
  
  // Get user's posted loads
  const getUserLoads = async () => {
    const user = getCurrentUserSync();
    if (!user || !user.id) throw new Error('User not logged in');

    try {
      const response = await apiRequest(`/loads/shipper/${user.id}`);
      return response;
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
    if (!user || !user.id) throw new Error('User not logged in');
    
    const ref = 'LD' + Date.now().toString().slice(-6);
    const sanitizedPayload = {
      ref: ref,
      origin: sanitize(payload.origin),
      destination: sanitize(payload.destination),
      date: payload.date,
      cargo_type: sanitize(payload.cargo_type),
      weight: parseFloat(payload.weight),
      notes: sanitize(payload.notes || ''),
      shipper_id: user.id
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
      let loads = response;
      
      if (filters.shipper_id) {
        loads = loads.filter(l => l.shipper_id === filters.shipper_id);
      }
      if (filters.origin) {
        loads = loads.filter(l => l.origin.toLowerCase().includes(filters.origin.toLowerCase()));
      }
      if (filters.destination) {
        loads = loads.filter(l => l.destination.toLowerCase().includes(filters.destination.toLowerCase()));
      }
      return loads;
    } catch (error) {
      console.error('Get loads error:', error);
      showNotification('Failed to get loads: ' + error.message, 'error');
      throw error;
    }
  };
  
  const updateLoad = async (loadId, patch) => {
    if (!loadId) throw new Error('Load ID is required');
    
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
    if (!user || !user.id) throw new Error('User not logged in');
    
    try {
      // For demo, we'll use email instead of membership number
      const message = await apiRequest('/messages', {
        method: 'POST',
        body: JSON.stringify({ 
          sender_id: user.id,
          receiver_email: toMembership + '@example.com', // Demo conversion
          body: sanitize(body) 
        })
      });
      showNotification('Message sent successfully', 'success');
      return message;
    } catch (error) {
      console.error('Send message error:', error);
      showNotification('Failed to send message: ' + error.message, 'error');
      throw error;
    }
  };
  
  const getMessages = async () => {
    const user = getCurrentUserSync();
    if (!user || !user.id) throw new Error('User not logged in');
    
    try {
      const response = await apiRequest(`/messages/${user.id}`);
      return response;
    } catch (error) {
      console.error('Get messages error:', error);
      showNotification('Failed to get messages: ' + error.message, 'error');
      throw error;
    }
  };
  
  // Admin API functions
  const getUsers = async () => {
    try {
      const response = await apiRequest('/admin/users');
      return response;
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

  // Check if user can access page
  const canAccessPage = (user, pageId) => {
    if (!user) return false;
    if (isAdmin(user)) return true;
    
    const page = PAGES[pageId];
    if (page && page.roles.includes(user.role)) {
      return true;
    }
    return false;
  };

  // Get load status
  const getLoadStatus = load => {
    if (load.status === 'secured') return 'secured';
    const expiryDate = new Date(load.expires_at);
    if (expiryDate < new Date()) return 'expired';
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

  // Render functions
  const renderShipperDashboard = async () => {
    const user = getCurrentUserSync();
    if (!user || user.role !== 'shipper') return;
    
    try {
      const loads = await getUserLoads();
      const tbody = el('tableMyLoadsShipper')?.querySelector('tbody');
      if (!tbody) return;
      
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
        const status = getLoadStatus(load);
        
        if (status === 'expired') {
          row.classList.add('expired');
        }
        
        row.innerHTML = `
          <td>${sanitize(load.ref)}</td>
          <td>${sanitize(load.origin)}</td>
          <td>${sanitize(load.destination)}</td>
          <td>${new Date(load.date).toLocaleDateString()}</td>
          <td>${new Date(load.expires_at).toLocaleDateString()}</td>
          <td>${sanitize(load.cargo_type)}</td>
          <td>${load.weight}</td>
          <td>${getStatusBadge(status)}</td>
          <td>
            <button class="btn" onclick="editUserLoad('${load.id}')">Edit</button>
            <button class="btn danger" onclick="deleteUserLoad('${load.id}')">Delete</button>
          </td>
        `;
        
        tbody.appendChild(row);
      });
    } catch (error) {
      console.error('Error rendering shipper dashboard:', error);
    }
  };

  const renderTransporterDashboard = async () => {
    const user = getCurrentUserSync();
    if (!user || user.role !== 'transporter') return;
    
    try {
      const loads = await getUserLoads();
      const tbody = el('tableMyLoadsTransporter')?.querySelector('tbody');
      if (!tbody) return;
      
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
        const status = getLoadStatus(load);
        
        if (status === 'expired') {
          row.classList.add('expired');
        }
        
        row.innerHTML = `
          <td>${sanitize(load.ref)}</td>
          <td>${sanitize(load.origin)}</td>
          <td>${sanitize(load.destination)}</td>
          <td>${new Date(load.date).toLocaleDateString()}</td>
          <td>${new Date(load.expires_at).toLocaleDateString()}</td>
          <td>${sanitize(load.cargo_type)}</td>
          <td>${load.weight}</td>
          <td>${getStatusBadge(status)}</td>
          <td>
            <button class="btn" onclick="editUserLoad('${load.id}')">Edit</button>
            <button class="btn danger" onclick="deleteUserLoad('${load.id}')">Delete</button>
          </td>
        `;
        
        tbody.appendChild(row);
      });
    } catch (error) {
      console.error('Error rendering transporter dashboard:', error);
    }
  };

  const renderMarket = async () => {
    try {
      const loads = await getLoads();
      const tbody = el('tableMarketLoads')?.querySelector('tbody');
      if (!tbody) return;
      
      while (tbody.firstChild) {
        tbody.removeChild(tbody.firstChild);
      }
      
      if (!loads || loads.length === 0) {
        const row = document.createElement('tr');
        const cell = document.createElement('td');
        cell.colSpan = 10;
        cell.className = 'muted';
        cell.textContent = 'No loads available.';
        row.appendChild(cell);
        tbody.appendChild(row);
        return;
      }
      
      loads.forEach(load => {
        const row = document.createElement('tr');
        const status = getLoadStatus(load);
        
        if (status === 'expired') {
          row.classList.add('expired');
        }
        
        row.innerHTML = `
          <td>${sanitize(load.ref)}</td>
          <td>${sanitize(load.origin)}</td>
          <td>${sanitize(load.destination)}</td>
          <td>${new Date(load.date).toLocaleDateString()}</td>
          <td>${new Date(load.expires_at).toLocaleDateString()}</td>
          <td>${sanitize(load.cargo_type)}</td>
          <td>${load.weight}</td>
          <td>${getStatusBadge(status)}</td>
          <td>${load.shipper_id ? 'MF' + load.shipper_id.toString().padStart(6, '0') : 'Unknown'}</td>
          <td>
            <button class="btn" onclick="contactShipper('${load.shipper_id}')">Contact</button>
          </td>
        `;
        
        tbody.appendChild(row);
      });
    } catch (error) {
      console.error('Error rendering market:', error);
    }
  };

  const renderMessages = async () => {
    try {
      const messages = await getMessages();
      const messageContainer = el('messageContainer');
      if (!messageContainer) return;
      
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
      
      messages.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
      
      messages.forEach(msg => {
        const messageDiv = document.createElement('div');
        const user = getCurrentUserSync();
        
        if (msg.sender_id === user.id) {
          messageDiv.className = 'message message-sent';
        } else {
          messageDiv.className = 'message message-received';
        }
        
        messageDiv.innerHTML = `
          <div class="message-header">
            <div class="message-sender">${msg.sender_name || 'User'}</div>
            <div class="message-time">${new Date(msg.created_at).toLocaleString()}</div>
          </div>
          <div class="message-body">${sanitize(msg.body)}</div>
        `;
        
        messageContainer.appendChild(messageDiv);
      });
    } catch (error) {
      console.error('Error rendering messages:', error);
    }
  };

  const renderControl = async () => {
    // Admin control panel rendering
    const user = getCurrentUserSync();
    if (!user || !isAdmin(user)) return;
    
    try {
      // Get users for admin table
      const users = await getUsers();
      const usersTable = el('tableUsers')?.querySelector('tbody');
      if (usersTable) {
        while (usersTable.firstChild) {
          usersTable.removeChild(usersTable.firstChild);
        }
        
        if (users && users.length > 0) {
          users.forEach(user => {
            const row = document.createElement('tr');
            row.innerHTML = `
              <td>${sanitize(user.name)}</td>
              <td>${sanitize(user.email)}</td>
              <td>${user.membership_number || 'MF' + user.id.toString().padStart(6, '0')}</td>
              <td>${sanitize(user.role)}</td>
              <td>${new Date(user.created_at).toLocaleDateString()}</td>
              <td>
                <button class="btn danger" onclick="adminDeleteUser('${user.email}')">Delete</button>
              </td>
            `;
            usersTable.appendChild(row);
          });
        }
      }
    } catch (error) {
      console.error('Error rendering control panel:', error);
    }
  };

  const renderHeader = async () => {
    const user = getCurrentUserSync();
    const navLinks = el('navLinks');
    const authUser = el('authUser');
    const btnLoginNav = el('btnLoginNav');
    const btnLogout = el('btnLogout');
    const roleChip = el('roleChip');
    
    if (user) {
      if (navLinks) {
        while (navLinks.firstChild) {
          navLinks.removeChild(navLinks.firstChild);
        }
      }
      
      if (authUser) authUser.textContent = user.name;
      if (btnLoginNav) btnLoginNav.classList.add('hidden');
      if (btnLogout) btnLogout.classList.remove('hidden');
      if (roleChip) {
        roleChip.textContent = user.role;
        roleChip.classList.remove('hidden');
      }
      
      const links = [];
      
      if (user.role === 'shipper') {
        links.push(
          { href: '#shipper-dashboard', text: 'Dashboard' },
          { href: '#shipper-post', text: 'Post Load' },
          { href: '#market', text: 'Market' },
          { href: '#messages', text: 'Messages' },
          { href: '#shipper-profile', text: 'Profile' }
        );
      } else if (user.role === 'transporter') {
        links.push(
          { href: '#transporter-dashboard', text: 'Dashboard' },
          { href: '#shipper-post', text: 'Post Load' },
          { href: '#market', text: 'Market' },
          { href: '#messages', text: 'Messages' },
          { href: '#transporter-profile', text: 'Profile' }
        );
      } else if (user.role === 'admin') {
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
        a.className = 'btn ghost';
        a.href = link.href;
        a.textContent = link.text;
        if (navLinks) {
          navLinks.appendChild(a);
        }
      });
    } else {
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

  // Main render function
  const render = async () => {
    await renderHeader();
    
    // Hide all pages first
    document.querySelectorAll('section').forEach(s => s.classList.add('hidden'));
    
    const hash = location.hash.slice(1) || 'index';
    const user = getCurrentUserSync();
    
    // Check access
    let canAccess = false;
    if (hash === 'index' || hash === 'login' || hash === 'register-options' || 
        hash === 'register-shipper' || hash === 'register-transporter') {
      canAccess = true;
    } else if (user) {
      canAccess = canAccessPage(user, hash);
    }
    
    if (!canAccess) {
      if (user) {
        location.hash = user.role === 'admin' ? '#control' : 
                       user.role === 'shipper' ? '#shipper-dashboard' : '#transporter-dashboard';
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
    }
  };

  // Global functions for onclick handlers
  window.editUserLoad = async (loadId) => {
    showNotification('Edit functionality coming soon', 'info');
  };
  
  window.deleteUserLoad = async (loadId) => {
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
  
  window.contactShipper = (shipperId) => {
    const membershipNumber = 'MF' + shipperId.toString().padStart(6, '0');
    location.hash = '#messages';
    setTimeout(() => {
      const msgTo = el('msgTo');
      if (msgTo) {
        msgTo.value = membershipNumber;
      }
    }, 100);
  };

  window.adminDeleteUser = async (email) => {
    if (confirm(`Are you sure you want to delete user ${email}?`)) {
      try {
        await deleteUser(email);
        await render();
      } catch (error) {
        console.error('Error deleting user:', error);
        showNotification('Failed to delete user', 'error');
      }
    }
  };

  // Event handlers
  const init = () => {
    // Form submissions
    el('formLogin')?.addEventListener('submit', async (e) => {
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
          location.hash = user.role === 'admin' ? '#control' : 
                         user.role === 'shipper' ? '#shipper-dashboard' : '#transporter-dashboard';
        }
      } catch (error) {
        console.error('Login error:', error);
      } finally {
        setButtonLoading('formLogin', false);
      }
    });
    
    el('formRegShipper')?.addEventListener('submit', async (e) => {
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
    
    el('formRegTransporter')?.addEventListener('submit', async (e) => {
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
    
    el('formPostLoad')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const formData = new FormData(e.target);
      const data = Object.fromEntries(formData);
      setButtonLoading('formPostLoad', true);
      try {
        await postLoad(data);
        e.target.reset();
        location.hash = getCurrentUserSync()?.role === 'shipper' ? '#shipper-dashboard' : '#transporter-dashboard';
      } catch (error) {
        console.error('Post load error:', error);
      } finally {
        setButtonLoading('formPostLoad', false);
      }
    });
    
    el('formSendMsg')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const to = el('msgTo')?.value;
      const body = el('msgBody')?.value;
      if (!to || !body) {
        showNotification('Please fill in all fields', 'error');
        return;
      }
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
      
      if (Object.keys(profileData).length === 0) {
        showNotification('No changes to save', 'info');
        return;
      }
      
      setButtonLoading('saveProfileShipper', true);
      try {
        await updateUserProfile(profileData);
        await render();
      } catch (error) {
        console.error('Profile update error:', error);
      } finally {
        setButtonLoading('saveProfileShipper', false);
      }
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
      
      if (Object.keys(profileData).length === 0) {
        showNotification('No changes to save', 'info');
        return;
      }
      
      setButtonLoading('saveProfileTransporter', true);
      try {
        await updateUserProfile(profileData);
        await render();
      } catch (error) {
        console.error('Profile update error:', error);
      } finally {
        setButtonLoading('saveProfileTransporter', false);
      }
    });
    
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
