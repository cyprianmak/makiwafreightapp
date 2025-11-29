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
      
      const data = await response.json().catch(() => ({}));
      
      if (!response.ok) {
        throw new Error(data.error || data.message || `API error: ${response.status}`);
      }
      
      return data;
    } catch (error) {
      if (error instanceof TypeError && error.message.includes('fetch')) {
        throw new Error('Network error. Please check your connection and try again.');
      }
      throw error;
    }
  };
  
  // Get current user synchronously
  const getCurrentUserSync = () => {
    try {
      const userData = sessionStorage.getItem('currentUser');
      if (userData) {
        const user = JSON.parse(userData);
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
        
        sessionStorage.setItem('currentUser', JSON.stringify(userData.user));
        sessionStorage.setItem('authToken', userData.token);
        showNotification('Login successful', 'success');
        setupSessionTimeout();
        return userData.user;
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
    const response = await apiRequest('/messages');
    
    if (response.success) {
        return response.data.messages;
    } else {
        throw new Error(response.error || response.message);
    }
  };

  // Check if user can access page - Super Admin can access everything
  const canAccessPage = (user, pageId) => {
    if (!user) return false;
    if (isAdmin(user)) return true;  // Both admin and super admin can access all pages
    
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

  // Profile rendering functions
  const renderShipperProfile = async () => {
    const user = getCurrentUserSync();
    if (!user || (user.role !== 'shipper' && !isAdmin(user))) return;
    
    try {
      const response = await apiRequest('/users/me');
      if (response.success) {
        const userData = response.data.user;
        
        // Populate profile data
        setText('shipperProfileName', userData.name || 'Shipper Name');
        setText('shipperProfileEmail', userData.email || 'email@example.com');
        setText('shipperProfileCompany', userData.company || 'Not specified');
        setText('shipperProfilePhone', userData.phone || 'Not specified');
        setText('shipperProfileAddress', userData.address || 'Not specified');
        setText('shipperProfileRole', isSuperAdmin(userData) ? 'Super Admin' : (userData.role === 'admin' ? 'Admin' : 'Shipper'));
        setText('shipperProfileMembership', userData.membership_number || 'MF000000');
        setText('shipperProfileCreated', new Date(userData.created_at).toLocaleDateString('en-US', { year: 'numeric', month: 'long' }));
        
        // Set form values
        const nameInput = el('profileShipperName');
        const phoneInput = el('profileShipperPhone');
        const addressInput = el('profileShipperAddress');
        
        if (nameInput) nameInput.value = userData.name || '';
        if (phoneInput) phoneInput.value = userData.phone || '';
        if (addressInput) addressInput.value = userData.address || '';
      }
    } catch (error) {
      console.error('Error loading shipper profile:', error);
    }
  };

  const renderTransporterProfile = async () => {
    const user = getCurrentUserSync();
    if (!user || (user.role !== 'transporter' && !isAdmin(user))) return;
    
    try {
      const response = await apiRequest('/users/me');
      if (response.success) {
        const userData = response.data.user;
        
        // Populate profile data
        setText('transporterProfileName', userData.name || 'Transporter Name');
        setText('transporterProfileEmail', userData.email || 'email@example.com');
        setText('transporterProfileCompany', userData.company || 'Not specified');
        setText('transporterProfileVehicle', userData.vehicle_info || 'Not specified');
        setText('transporterProfilePhone', userData.phone || 'Not specified');
        setText('transporterProfileAddress', userData.address || 'Not specified');
        setText('transporterProfileRole', isSuperAdmin(userData) ? 'Super Admin' : (userData.role === 'admin' ? 'Admin' : 'Transporter'));
        setText('transporterProfileMembership', userData.membership_number || 'MF000000');
        setText('transporterProfileCreated', new Date(userData.created_at).toLocaleDateString('en-US', { year: 'numeric', month: 'long' }));
        
        // Set form values
        const nameInput = el('profileTransporterName');
        const phoneInput = el('profileTransporterPhone');
        const addressInput = el('profileTransporterAddress');
        
        if (nameInput) nameInput.value = userData.name || '';
        if (phoneInput) phoneInput.value = userData.phone || '';
        if (addressInput) addressInput.value = userData.address || '';
      }
    } catch (error) {
      console.error('Error loading transporter profile:', error);
    }
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
        showNotification('Failed to load market data', 'error');
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
      showNotification('Failed to load messages', 'error');
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
                usersTbody.innerHTML = '<tr><td colspan="6" class="muted">No users found.</td></tr>';
            } else {
                users.forEach(user => {
                    const row = document.createElement('tr');
                    const isCurrentSuperAdmin = user.email === SUPER_ADMIN_EMAIL;
                    row.innerHTML = `
                        <td>${sanitize(user.name)} ${isCurrentSuperAdmin ? '👑' : ''}</td>
                        <td>${sanitize(user.email)}</td>
                        <td>${sanitize(user.membership_number)}</td>
                        <td><span class="chip ${isCurrentSuperAdmin ? 'chip-warning' : ''}">${isCurrentSuperAdmin ? 'SUPER ADMIN' : sanitize(user.role)}</span></td>
                        <td>${new Date(user.created_at).toLocaleDateString()}</td>
                        <td>
                            ${!isCurrentSuperAdmin ? `<button class="btn small danger" onclick="deleteUser('${user.email}')">Delete</button>` : '<span class="muted">Protected</span>'}
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

        // Show super admin badge
        if (isSuperAdmin(user)) {
          const adminTitle = el('adminPanelTitle');
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
      
      // Create navigation links based on role
      const links = [];
      
      if (user.role === 'shipper' || isAdmin(user)) {
        links.push(
          { href: '#shipper-dashboard', text: 'Dashboard' },
          { href: '#shipper-post', text: 'Post Load' },
          { href: '#market', text: 'Market' },
          { href: '#messages', text: 'Messages' },
          { href: '#shipper-profile', text: 'Profile' }
        );
      }
      
      if (user.role === 'transporter' || isAdmin(user)) {
        links.push(
          { href: '#transporter-dashboard', text: 'Transporter Dashboard' }
        );
        
        if (!links.find(link => link.href === '#shipper-profile')) {
          links.push({ href: '#transporter-profile', text: 'Profile' });
        }
      }
      
      if (isAdmin(user)) {
        links.unshift({ href: '#control', text: 'Admin Control' });
      }
      
      // Remove duplicates
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
        canAccess = canAccessPage(user, hash);
      }
      
      if (!canAccess) {
        if (user) {
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
      
      const submitButton = e.target.querySelector('button[type="submit']');
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
