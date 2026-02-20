/**
 * access.js -- Access page for SentinelGate admin UI.
 *
 * API Keys management: list all keys with identity resolution,
 * create new keys with one-time cleartext display, and revoke
 * existing keys.
 *
 * Identities management: collapsible CRUD section with Add/Edit/Delete
 * modals and role badge display.
 *
 * MCP Client Config: ready-to-paste JSON snippet with Copy button.
 *
 * Data sources:
 *   GET    /admin/api/keys              -> all API keys
 *   GET    /admin/api/identities        -> identity list for dropdown + name resolution
 *   POST   /admin/api/keys              -> create new API key
 *   DELETE /admin/api/keys/{id}         -> revoke API key
 *   POST   /admin/api/identities        -> create identity
 *   PUT    /admin/api/identities/{id}   -> update identity
 *   DELETE /admin/api/identities/{id}   -> delete identity
 *
 * Design features:
 *   - API Keys table with name, identity, created, status, actions
 *   - Create Key modal with name + identity dropdown
 *   - One-time cleartext key display with Copy button
 *   - Revoke button with confirmation dialog
 *   - Identities collapsible card with Add/Edit/Delete modals
 *   - Role badges per identity
 *   - MCP Client Config JSON snippet with Copy button
 *   - Empty state when no keys/identities exist
 *   - All user data rendered via textContent (XSS-safe)
 *
 * Requirements:
 *   ACCS-01  API Keys table listing all keys
 *   ACCS-02  Create Key modal with identity selection
 *   ACCS-03  One-time cleartext key display with Copy button
 *   ACCS-04  Revoke key with confirmation
 *   ACCS-05  Identities section with CRUD
 *   ACCS-06  MCP Client Config snippet with Copy
 */
'use strict';

(function () {
  window.SG = window.SG || {};

  // -- State ------------------------------------------------------------------

  var styleInjected = false;
  var keys = [];
  var identities = [];
  var identityMap = {};
  var identitiesCollapsed = false;

  // -- Access-specific styles -------------------------------------------------

  var ACCESS_CSS = [
    /* Layout */
    '.access-header {',
    '  display: flex;',
    '  align-items: center;',
    '  justify-content: space-between;',
    '  margin-bottom: var(--space-6);',
    '}',
    '.access-header h1 {',
    '  font-size: var(--text-2xl);',
    '  font-weight: var(--font-bold);',
    '  color: var(--text-primary);',
    '  margin: 0;',
    '  letter-spacing: -0.02em;',
    '}',
    '.access-header-desc {',
    '  font-size: var(--text-sm);',
    '  color: var(--text-muted);',
    '  margin: 0;',
    '  margin-top: var(--space-1);',
    '}',

    /* Section spacing */
    '.access-section {',
    '  margin-bottom: var(--space-6);',
    '}',

    /* Key display block */
    '.key-display {',
    '  background: var(--bg-surface);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  padding: var(--space-3) var(--space-4);',
    '  font-family: var(--font-mono);',
    '  font-size: var(--text-sm);',
    '  color: var(--text-primary);',
    '  word-break: break-all;',
    '  line-height: 1.6;',
    '  margin-bottom: var(--space-3);',
    '  user-select: all;',
    '}',

    /* Warning text */
    '.key-display-warning {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '  color: var(--danger);',
    '  font-size: var(--text-sm);',
    '  font-weight: var(--font-medium);',
    '  margin-bottom: var(--space-3);',
    '}',

    /* Copy button */
    '.key-copy-btn {',
    '  display: inline-flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '  padding: var(--space-2) var(--space-3);',
    '  background: var(--accent);',
    '  color: var(--accent-contrast);',
    '  border: none;',
    '  border-radius: var(--radius-md);',
    '  font-size: var(--text-sm);',
    '  font-weight: var(--font-medium);',
    '  cursor: pointer;',
    '  transition: all var(--transition-fast);',
    '}',
    '.key-copy-btn:hover {',
    '  opacity: 0.9;',
    '}',
    '.key-copy-btn.copied {',
    '  background: var(--success);',
    '}',

    /* Key result footer */
    '.key-result-footer {',
    '  display: flex;',
    '  align-items: center;',
    '  justify-content: space-between;',
    '  margin-top: var(--space-3);',
    '}',

    /* Table status badges */
    '.key-status-active {',
    '  color: var(--success);',
    '  font-weight: var(--font-medium);',
    '  font-size: var(--text-sm);',
    '}',
    '.key-status-revoked {',
    '  color: var(--danger);',
    '  font-weight: var(--font-medium);',
    '  font-size: var(--text-sm);',
    '}',

    /* Entrance animation */
    '@keyframes accessFadeUp {',
    '  from { opacity: 0; transform: translateY(12px); }',
    '  to   { opacity: 1; transform: translateY(0); }',
    '}',
    '.access-enter {',
    '  animation: accessFadeUp 0.4s ease both;',
    '}',
    '.access-enter-1 { animation-delay: 0.04s; }',
    '.access-enter-2 { animation-delay: 0.08s; }',
    '.access-enter-3 { animation-delay: 0.12s; }',
    '.access-enter-4 { animation-delay: 0.16s; }',

    /* Config snippet */
    '.config-snippet-wrapper {',
    '  position: relative;',
    '  margin-bottom: var(--space-3);',
    '}',
    '.config-snippet {',
    '  background: var(--bg-primary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  padding: var(--space-4);',
    '  font-family: var(--font-mono);',
    '  font-size: var(--text-sm);',
    '  color: var(--text-primary);',
    '  line-height: 1.6;',
    '  overflow-x: auto;',
    '  white-space: pre;',
    '  margin: 0;',
    '}',
    '.config-copy-btn {',
    '  position: absolute;',
    '  top: var(--space-2);',
    '  right: var(--space-2);',
    '  display: inline-flex;',
    '  align-items: center;',
    '  gap: var(--space-1);',
    '  padding: var(--space-1) var(--space-2);',
    '  background: var(--bg-surface);',
    '  color: var(--text-secondary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  font-size: var(--text-xs);',
    '  cursor: pointer;',
    '  transition: all var(--transition-fast);',
    '  opacity: 0.8;',
    '}',
    '.config-copy-btn:hover {',
    '  opacity: 1;',
    '  background: var(--bg-hover);',
    '}',
    '.config-copy-btn.copied {',
    '  background: var(--success);',
    '  color: var(--accent-contrast);',
    '  border-color: var(--success);',
    '}',

    /* Collapsible card header */
    '.access-collapse-header {',
    '  cursor: pointer;',
    '  user-select: none;',
    '}',
    '.access-collapse-header:hover {',
    '  background: var(--bg-surface);',
    '}',
    '.access-collapse-chevron {',
    '  display: inline-block;',
    '  transition: transform var(--transition-fast);',
    '  margin-left: var(--space-2);',
    '}',
    '.access-collapse-chevron.collapsed {',
    '  transform: rotate(-90deg);',
    '}',
    '.access-collapse-body {',
    '  overflow: hidden;',
    '  transition: max-height 0.3s ease, opacity 0.3s ease;',
    '  max-height: 2000px;',
    '  opacity: 1;',
    '}',
    '.access-collapse-body.collapsed {',
    '  max-height: 0;',
    '  opacity: 0;',
    '}',

    /* Role badges */
    '.identity-roles {',
    '  display: flex;',
    '  flex-wrap: wrap;',
    '  gap: var(--space-1);',
    '}',
    '.role-badge {',
    '  display: inline-block;',
    '  padding: 1px var(--space-2);',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-medium);',
    '  border-radius: var(--radius-full);',
    '  background: var(--accent-subtle);',
    '  color: var(--accent);',
    '  border: 1px solid rgba(99, 102, 241, 0.2);',
    '}'
  ].join('\n');

  function injectStyles() {
    if (styleInjected) return;
    var s = document.createElement('style');
    s.setAttribute('data-access', '');
    s.textContent = ACCESS_CSS;
    document.head.appendChild(s);
    styleInjected = true;
  }

  // -- DOM helpers ------------------------------------------------------------

  function mk(tag, className, attrs) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (attrs) {
      var ks = Object.keys(attrs);
      for (var i = 0; i < ks.length; i++) {
        var k = ks[i];
        if (k === 'style') {
          node.style.cssText = attrs[k];
        } else {
          node.setAttribute(k, attrs[k]);
        }
      }
    }
    return node;
  }

  // -- Format helpers ---------------------------------------------------------

  function formatDate(iso) {
    if (!iso) return '-';
    try {
      var d = new Date(iso);
      if (isNaN(d.getTime())) return iso;
      return d.toLocaleDateString(undefined, {
        year: 'numeric', month: 'short', day: 'numeric'
      }) + ' ' + d.toLocaleTimeString(undefined, {
        hour: '2-digit', minute: '2-digit'
      });
    } catch (e) {
      return iso;
    }
  }

  function resolveIdentityName(identityId) {
    if (!identityId) return 'Unknown';
    return identityMap[identityId] || identityId.substring(0, 8) + '...';
  }

  // -- Build page DOM ---------------------------------------------------------

  function buildPage(container) {
    var root = mk('div', '');

    // Header
    var header = mk('div', 'access-header access-enter access-enter-1');
    var headerLeft = mk('div', '');
    var h1 = mk('h1');
    h1.textContent = 'Access';
    headerLeft.appendChild(h1);
    var desc = mk('p', 'access-header-desc');
    desc.textContent = 'Manage API keys for MCP client authentication';
    headerLeft.appendChild(desc);
    header.appendChild(headerLeft);
    root.appendChild(header);

    // API Keys section
    var section = mk('div', 'access-section access-enter access-enter-2');

    var card = mk('div', 'card');
    var cardHeader = mk('div', 'card-header');
    var cardTitle = mk('span', 'card-title');
    cardTitle.innerHTML = SG.icon('key', 16) + ' ';
    cardTitle.appendChild(document.createTextNode('API Keys'));
    cardHeader.appendChild(cardTitle);

    var createBtn = mk('button', 'btn btn-primary btn-sm');
    createBtn.innerHTML = SG.icon('plus', 14) + ' ';
    createBtn.appendChild(document.createTextNode('Create Key'));
    createBtn.addEventListener('click', function () {
      openCreateKeyModal();
    });
    cardHeader.appendChild(createBtn);
    card.appendChild(cardHeader);

    var cardBody = mk('div', 'card-body');
    cardBody.id = 'keys-table-container';

    // Skeleton loading
    for (var s = 0; s < 3; s++) {
      var skel = mk('div', 'skeleton', {
        style: 'height: 44px; margin-bottom: var(--space-2); border-radius: var(--radius-md);'
      });
      cardBody.appendChild(skel);
    }

    card.appendChild(cardBody);
    section.appendChild(card);
    root.appendChild(section);

    // Identities section
    var idSection = mk('div', 'access-section access-enter access-enter-3');
    var idCard = mk('div', 'card');

    var idCardHeader = mk('div', 'card-header access-collapse-header');
    var idCardTitleArea = mk('div', '', { style: 'display: flex; align-items: center; flex: 1;' });
    var idCardTitle = mk('span', 'card-title');
    idCardTitle.innerHTML = SG.icon('user', 16) + ' ';
    idCardTitle.appendChild(document.createTextNode('Identities'));
    idCardTitleArea.appendChild(idCardTitle);

    var chevron = mk('span', 'access-collapse-chevron');
    chevron.innerHTML = SG.icon('chevronDown', 14);
    idCardTitleArea.appendChild(chevron);
    idCardHeader.appendChild(idCardTitleArea);

    var addIdBtn = mk('button', 'btn btn-primary btn-sm');
    addIdBtn.innerHTML = SG.icon('plus', 14) + ' ';
    addIdBtn.appendChild(document.createTextNode('Add Identity'));
    addIdBtn.addEventListener('click', function (e) {
      e.stopPropagation();
      openAddIdentityModal();
    });
    idCardHeader.appendChild(addIdBtn);

    // Collapse toggle on header click
    idCardHeader.addEventListener('click', function () {
      identitiesCollapsed = !identitiesCollapsed;
      var body = document.getElementById('identities-table-container');
      if (body) {
        if (identitiesCollapsed) {
          body.classList.add('collapsed');
        } else {
          body.classList.remove('collapsed');
        }
      }
      if (identitiesCollapsed) {
        chevron.classList.add('collapsed');
      } else {
        chevron.classList.remove('collapsed');
      }
    });

    idCard.appendChild(idCardHeader);

    var idCardBody = mk('div', 'card-body access-collapse-body');
    idCardBody.id = 'identities-table-container';
    if (identitiesCollapsed) {
      idCardBody.classList.add('collapsed');
      chevron.classList.add('collapsed');
    }

    // Skeleton loading
    for (var sk = 0; sk < 3; sk++) {
      var idSkel = mk('div', 'skeleton', {
        style: 'height: 44px; margin-bottom: var(--space-2); border-radius: var(--radius-md);'
      });
      idCardBody.appendChild(idSkel);
    }

    idCard.appendChild(idCardBody);
    idSection.appendChild(idCard);
    root.appendChild(idSection);

    // MCP Client Configuration section
    var configSection = mk('div', 'access-section access-enter access-enter-4');
    var configCard = mk('div', 'card');
    var configCardHeader = mk('div', 'card-header');
    var configCardTitle = mk('span', 'card-title');
    configCardTitle.innerHTML = SG.icon('code', 16) + ' ';
    configCardTitle.appendChild(document.createTextNode('MCP Client Configuration'));
    configCardHeader.appendChild(configCardTitle);
    configCard.appendChild(configCardHeader);

    var configCardBody = mk('div', 'card-body');

    var configInfo = mk('p', '', {
      style: 'font-size: var(--text-sm); color: var(--text-secondary); margin: 0 0 var(--space-4) 0;'
    });
    configInfo.textContent = 'Use this JSON snippet in your MCP client configuration to connect to SentinelGate.';
    configCardBody.appendChild(configInfo);

    var proxyAddress = window.location.host || 'localhost:8080';
    var configJSON = JSON.stringify({
      mcpServers: {
        sentinelgate: {
          url: 'http://' + proxyAddress + '/mcp',
          headers: {
            Authorization: 'Bearer {your-api-key}'
          }
        }
      }
    }, null, 2);

    var snippetWrapper = mk('div', 'config-snippet-wrapper');
    var snippetPre = mk('pre', 'config-snippet');
    snippetPre.textContent = configJSON;
    snippetWrapper.appendChild(snippetPre);

    var configCopyBtn = mk('button', 'config-copy-btn');
    configCopyBtn.innerHTML = SG.icon('copy', 12) + ' ';
    var configCopyLabel = mk('span', '');
    configCopyLabel.textContent = 'Copy';
    configCopyBtn.appendChild(configCopyLabel);

    configCopyBtn.addEventListener('click', function () {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(configJSON).then(function () {
          configCopyBtn.classList.add('copied');
          configCopyLabel.textContent = 'Copied!';
          SG.toast.show('Copied to clipboard', 'success');
          setTimeout(function () {
            configCopyBtn.classList.remove('copied');
            configCopyLabel.textContent = 'Copy';
          }, 2000);
        }).catch(function () {
          fallbackConfigCopy(configJSON, configCopyBtn, configCopyLabel);
        });
      } else {
        fallbackConfigCopy(configJSON, configCopyBtn, configCopyLabel);
      }
    });
    snippetWrapper.appendChild(configCopyBtn);
    configCardBody.appendChild(snippetWrapper);

    var configHelp = mk('p', '', {
      style: 'font-size: var(--text-xs); color: var(--text-muted); margin: 0;'
    });
    configHelp.textContent = 'Replace {your-api-key} with an actual API key from the section above.';
    configCardBody.appendChild(configHelp);

    configCard.appendChild(configCardBody);
    configSection.appendChild(configCard);
    root.appendChild(configSection);

    container.appendChild(root);
  }

  // -- Render keys table ------------------------------------------------------

  function renderKeysTable() {
    var container = document.getElementById('keys-table-container');
    if (!container) return;
    container.innerHTML = '';

    if (keys.length === 0) {
      var empty = mk('div', 'empty-state');
      var emptyIcon = mk('div', 'empty-state-icon');
      emptyIcon.innerHTML = SG.icon('key', 32);
      empty.appendChild(emptyIcon);
      var emptyTitle = mk('p', 'empty-state-title');
      emptyTitle.textContent = 'No API keys';
      empty.appendChild(emptyTitle);
      var emptyDesc = mk('p', 'empty-state-description');
      emptyDesc.textContent = 'Create an API key for MCP client authentication';
      empty.appendChild(emptyDesc);
      container.appendChild(empty);
      return;
    }

    var table = mk('table', 'table');

    // Table head
    var thead = mk('thead', '');
    var headRow = mk('tr', '');
    var cols = ['Name', 'Identity', 'Created', 'Status', 'Actions'];
    for (var c = 0; c < cols.length; c++) {
      var th = mk('th', '');
      th.textContent = cols[c];
      headRow.appendChild(th);
    }
    thead.appendChild(headRow);
    table.appendChild(thead);

    // Table body
    var tbody = mk('tbody', '');
    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      var row = mk('tr', '');

      // Name
      var tdName = mk('td', '');
      var nameSpan = mk('span', '', { style: 'font-weight: var(--font-medium);' });
      nameSpan.textContent = key.name || '-';
      tdName.appendChild(nameSpan);
      row.appendChild(tdName);

      // Identity
      var tdIdentity = mk('td', '');
      tdIdentity.textContent = resolveIdentityName(key.identity_id);
      row.appendChild(tdIdentity);

      // Created
      var tdCreated = mk('td', '');
      tdCreated.textContent = formatDate(key.created_at);
      row.appendChild(tdCreated);

      // Status
      var tdStatus = mk('td', '');
      if (key.revoked) {
        var revokedBadge = mk('span', 'badge badge-danger');
        revokedBadge.textContent = 'Revoked';
        tdStatus.appendChild(revokedBadge);
      } else {
        var activeBadge = mk('span', 'badge badge-success');
        activeBadge.textContent = 'Active';
        tdStatus.appendChild(activeBadge);
      }
      row.appendChild(tdStatus);

      // Actions
      var tdActions = mk('td', '');
      if (!key.revoked && !key.read_only) {
        var revokeBtn = mk('button', 'btn btn-danger btn-sm');
        revokeBtn.textContent = 'Revoke';
        (function (keyId, keyName) {
          revokeBtn.addEventListener('click', function () {
            revokeKey(keyId, keyName);
          });
        })(key.id, key.name);
        tdActions.appendChild(revokeBtn);
      } else if (key.read_only) {
        var roLabel = mk('span', '', {
          style: 'font-size: var(--text-xs); color: var(--text-muted);'
        });
        roLabel.textContent = 'Read-only';
        tdActions.appendChild(roLabel);
      } else {
        var revLabel = mk('span', '', {
          style: 'font-size: var(--text-xs); color: var(--text-muted);'
        });
        revLabel.textContent = '-';
        tdActions.appendChild(revLabel);
      }
      row.appendChild(tdActions);

      tbody.appendChild(row);
    }

    table.appendChild(tbody);
    container.appendChild(table);
  }

  // -- Render identities table ------------------------------------------------

  function renderIdentitiesTable() {
    var container = document.getElementById('identities-table-container');
    if (!container) return;
    container.innerHTML = '';

    // Preserve collapse state
    if (identitiesCollapsed) {
      container.classList.add('collapsed');
    }

    if (identities.length === 0) {
      var empty = mk('div', 'empty-state');
      var emptyIcon = mk('div', 'empty-state-icon');
      emptyIcon.innerHTML = SG.icon('user', 32);
      empty.appendChild(emptyIcon);
      var emptyTitle = mk('p', 'empty-state-title');
      emptyTitle.textContent = 'No identities';
      empty.appendChild(emptyTitle);
      var emptyDesc = mk('p', 'empty-state-description');
      emptyDesc.textContent = 'Add an identity to assign API keys and roles';
      empty.appendChild(emptyDesc);
      container.appendChild(empty);
      return;
    }

    var table = mk('table', 'table');

    // Table head
    var thead = mk('thead', '');
    var headRow = mk('tr', '');
    var cols = ['Name', 'Roles', 'Created', 'Actions'];
    for (var c = 0; c < cols.length; c++) {
      var th = mk('th', '');
      th.textContent = cols[c];
      headRow.appendChild(th);
    }
    thead.appendChild(headRow);
    table.appendChild(thead);

    // Table body
    var tbody = mk('tbody', '');
    for (var i = 0; i < identities.length; i++) {
      var identity = identities[i];
      var row = mk('tr', '');

      // Name
      var tdName = mk('td', '');
      var nameSpan = mk('span', '', { style: 'font-weight: var(--font-medium);' });
      nameSpan.textContent = identity.name || '-';
      tdName.appendChild(nameSpan);
      row.appendChild(tdName);

      // Roles
      var tdRoles = mk('td', '');
      var rolesContainer = mk('div', 'identity-roles');
      var roles = identity.roles || [];
      if (roles.length === 0) {
        var noRoles = mk('span', '', {
          style: 'font-size: var(--text-xs); color: var(--text-muted);'
        });
        noRoles.textContent = 'No roles';
        rolesContainer.appendChild(noRoles);
      } else {
        for (var r = 0; r < roles.length; r++) {
          var roleBadge = mk('span', 'role-badge');
          roleBadge.textContent = roles[r];
          rolesContainer.appendChild(roleBadge);
        }
      }
      tdRoles.appendChild(rolesContainer);
      row.appendChild(tdRoles);

      // Created
      var tdCreated = mk('td', '');
      tdCreated.textContent = formatDate(identity.created_at);
      row.appendChild(tdCreated);

      // Actions
      var tdActions = mk('td', '');
      if (!identity.read_only) {
        var actionsWrap = mk('div', '', { style: 'display: flex; gap: var(--space-2);' });
        var editBtn = mk('button', 'btn btn-secondary btn-sm');
        editBtn.textContent = 'Edit';
        (function (id) {
          editBtn.addEventListener('click', function () {
            openEditIdentityModal(id);
          });
        })(identity);
        actionsWrap.appendChild(editBtn);

        var deleteBtn = mk('button', 'btn btn-danger btn-sm');
        deleteBtn.textContent = 'Delete';
        (function (id) {
          deleteBtn.addEventListener('click', function () {
            deleteIdentity(id.id, id.name);
          });
        })(identity);
        actionsWrap.appendChild(deleteBtn);

        tdActions.appendChild(actionsWrap);
      } else {
        var roLabel = mk('span', '', {
          style: 'font-size: var(--text-xs); color: var(--text-muted);'
        });
        roLabel.textContent = 'Read-only';
        tdActions.appendChild(roLabel);
      }
      row.appendChild(tdActions);

      tbody.appendChild(row);
    }

    table.appendChild(tbody);
    container.appendChild(table);
  }

  // -- Add Identity modal -----------------------------------------------------

  function openAddIdentityModal() {
    var form = mk('form', '');
    form.addEventListener('submit', function (e) { e.preventDefault(); });

    // Name field
    var nameGroup = mk('div', 'form-group');
    var nameLabel = mk('label', 'form-label');
    nameLabel.textContent = 'Name';
    nameGroup.appendChild(nameLabel);
    var nameInput = mk('input', 'form-input', {
      type: 'text',
      placeholder: 'e.g. developer-team',
      required: 'required'
    });
    nameGroup.appendChild(nameInput);
    var nameHelp = mk('span', 'form-help');
    nameHelp.textContent = 'A unique name for this identity';
    nameGroup.appendChild(nameHelp);
    form.appendChild(nameGroup);

    // Roles field
    var rolesGroup = mk('div', 'form-group');
    var rolesLabel = mk('label', 'form-label');
    rolesLabel.textContent = 'Roles';
    rolesGroup.appendChild(rolesLabel);
    var rolesTextarea = mk('textarea', 'form-input', {
      placeholder: 'admin\ndeveloper\nviewer',
      rows: '4'
    });
    rolesGroup.appendChild(rolesTextarea);
    var rolesHelp = mk('span', 'form-help');
    rolesHelp.textContent = 'One role per line (optional)';
    rolesGroup.appendChild(rolesHelp);
    form.appendChild(rolesGroup);

    // Footer with buttons
    var footer = mk('div', '', { style: 'display: contents;' });
    var cancelBtn = mk('button', 'btn btn-secondary');
    cancelBtn.textContent = 'Cancel';
    cancelBtn.type = 'button';
    cancelBtn.addEventListener('click', function () {
      SG.modal.close();
    });
    footer.appendChild(cancelBtn);

    var submitBtn = mk('button', 'btn btn-primary');
    submitBtn.textContent = 'Add Identity';
    submitBtn.type = 'submit';
    footer.appendChild(submitBtn);

    SG.modal.open({
      title: 'Add Identity',
      body: form,
      footer: footer,
      width: '480px'
    });

    // Handle form submission
    submitBtn.addEventListener('click', function () {
      var name = nameInput.value.trim();
      if (!name) {
        nameInput.focus();
        return;
      }

      var rolesArray = parseRoles(rolesTextarea.value);

      submitBtn.disabled = true;
      submitBtn.textContent = 'Adding...';

      SG.api.post('/identities', {
        name: name,
        roles: rolesArray
      }).then(function () {
        SG.modal.close();
        SG.toast.show('Identity added', 'success');
        loadData();
      }).catch(function (err) {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Add Identity';
        SG.toast.show(err.message || 'Failed to add identity', 'error');
      });
    });

    // Focus name input
    setTimeout(function () { nameInput.focus(); }, 100);
  }

  // -- Edit Identity modal ----------------------------------------------------

  function openEditIdentityModal(identity) {
    var form = mk('form', '');
    form.addEventListener('submit', function (e) { e.preventDefault(); });

    // Name field
    var nameGroup = mk('div', 'form-group');
    var nameLabel = mk('label', 'form-label');
    nameLabel.textContent = 'Name';
    nameGroup.appendChild(nameLabel);
    var nameInput = mk('input', 'form-input', {
      type: 'text',
      placeholder: 'e.g. developer-team',
      required: 'required'
    });
    nameInput.value = identity.name || '';
    if (identity.read_only) {
      nameInput.disabled = true;
    }
    nameGroup.appendChild(nameInput);
    form.appendChild(nameGroup);

    // Roles field
    var rolesGroup = mk('div', 'form-group');
    var rolesLabel = mk('label', 'form-label');
    rolesLabel.textContent = 'Roles';
    rolesGroup.appendChild(rolesLabel);
    var rolesTextarea = mk('textarea', 'form-input', {
      placeholder: 'admin\ndeveloper\nviewer',
      rows: '4'
    });
    rolesTextarea.value = (identity.roles || []).join('\n');
    rolesGroup.appendChild(rolesTextarea);
    var rolesHelp = mk('span', 'form-help');
    rolesHelp.textContent = 'One role per line (optional)';
    rolesGroup.appendChild(rolesHelp);
    form.appendChild(rolesGroup);

    // Footer with buttons
    var footer = mk('div', '', { style: 'display: contents;' });
    var cancelBtn = mk('button', 'btn btn-secondary');
    cancelBtn.textContent = 'Cancel';
    cancelBtn.type = 'button';
    cancelBtn.addEventListener('click', function () {
      SG.modal.close();
    });
    footer.appendChild(cancelBtn);

    var submitBtn = mk('button', 'btn btn-primary');
    submitBtn.textContent = 'Save Changes';
    submitBtn.type = 'submit';
    footer.appendChild(submitBtn);

    SG.modal.open({
      title: 'Edit Identity',
      body: form,
      footer: footer,
      width: '480px'
    });

    // Handle form submission
    submitBtn.addEventListener('click', function () {
      var name = nameInput.value.trim();
      if (!name) {
        nameInput.focus();
        return;
      }

      var rolesArray = parseRoles(rolesTextarea.value);

      submitBtn.disabled = true;
      submitBtn.textContent = 'Saving...';

      SG.api.put('/identities/' + identity.id, {
        name: name,
        roles: rolesArray
      }).then(function () {
        SG.modal.close();
        SG.toast.show('Identity updated', 'success');
        loadData();
      }).catch(function (err) {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Save Changes';
        SG.toast.show(err.message || 'Failed to update identity', 'error');
      });
    });

    // Focus name input
    setTimeout(function () { nameInput.focus(); }, 100);
  }

  // -- Delete Identity --------------------------------------------------------

  function deleteIdentity(identityId, identityName) {
    if (!confirm('Delete identity "' + identityName + '"?\n\nThis will also delete all API keys associated with this identity. This action cannot be undone.')) {
      return;
    }

    SG.api.del('/identities/' + identityId).then(function () {
      SG.toast.show('Identity deleted', 'success');
      loadData();
    }).catch(function (err) {
      SG.toast.show(err.message || 'Failed to delete identity', 'error');
    });
  }

  // -- Parse roles helper -----------------------------------------------------

  function parseRoles(text) {
    if (!text) return [];
    return text.split('\n')
      .map(function (line) { return line.trim(); })
      .filter(function (line) { return line.length > 0; });
  }

  // -- Data loading -----------------------------------------------------------

  function loadData() {
    Promise.all([
      SG.api.get('/keys'),
      SG.api.get('/identities')
    ]).then(function (results) {
      keys = results[0] || [];
      identities = results[1] || [];

      // Build identity map for name resolution
      identityMap = {};
      for (var i = 0; i < identities.length; i++) {
        identityMap[identities[i].id] = identities[i].name;
      }

      renderKeysTable();
      renderIdentitiesTable();
    }).catch(function (err) {
      SG.toast.show('Failed to load data: ' + (err.message || 'Unknown error'), 'error');
    });
  }

  // -- Create Key modal -------------------------------------------------------

  function openCreateKeyModal() {
    var form = mk('form', '');
    form.addEventListener('submit', function (e) { e.preventDefault(); });

    // Name field
    var nameGroup = mk('div', 'form-group');
    var nameLabel = mk('label', 'form-label');
    nameLabel.textContent = 'Name';
    nameGroup.appendChild(nameLabel);
    var nameInput = mk('input', 'form-input', {
      type: 'text',
      placeholder: 'e.g. my-mcp-client',
      required: 'required'
    });
    nameGroup.appendChild(nameInput);
    var nameHelp = mk('span', 'form-help');
    nameHelp.textContent = 'A descriptive name for this API key';
    nameGroup.appendChild(nameHelp);
    form.appendChild(nameGroup);

    // Identity field
    var identityGroup = mk('div', 'form-group');
    var identityLabel = mk('label', 'form-label');
    identityLabel.textContent = 'Identity';
    identityGroup.appendChild(identityLabel);
    var identitySelect = mk('select', 'form-select', { required: 'required' });

    var placeholder = mk('option', '', { value: '', disabled: 'disabled', selected: 'selected' });
    placeholder.textContent = 'Select an identity...';
    identitySelect.appendChild(placeholder);

    for (var i = 0; i < identities.length; i++) {
      var opt = mk('option', '', { value: identities[i].id });
      opt.textContent = identities[i].name;
      identitySelect.appendChild(opt);
    }

    identityGroup.appendChild(identitySelect);
    var identityHelp = mk('span', 'form-help');
    identityHelp.textContent = 'The identity this key will authenticate as';
    identityGroup.appendChild(identityHelp);
    form.appendChild(identityGroup);

    // Footer with buttons
    var footer = mk('div', '', { style: 'display: contents;' });
    var cancelBtn = mk('button', 'btn btn-secondary');
    cancelBtn.textContent = 'Cancel';
    cancelBtn.type = 'button';
    cancelBtn.addEventListener('click', function () {
      SG.modal.close();
    });
    footer.appendChild(cancelBtn);

    var submitBtn = mk('button', 'btn btn-primary');
    submitBtn.textContent = 'Create Key';
    submitBtn.type = 'submit';
    footer.appendChild(submitBtn);

    var modalBody = SG.modal.open({
      title: 'Create API Key',
      body: form,
      footer: footer,
      width: '480px'
    });

    // Handle form submission
    submitBtn.addEventListener('click', function () {
      var name = nameInput.value.trim();
      var identityId = identitySelect.value;

      if (!name) {
        nameInput.focus();
        return;
      }
      if (!identityId) {
        identitySelect.focus();
        return;
      }

      submitBtn.disabled = true;
      submitBtn.textContent = 'Creating...';

      SG.api.post('/keys', {
        name: name,
        identity_id: identityId
      }).then(function (result) {
        showKeyResult(modalBody, result);
      }).catch(function (err) {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Create Key';
        SG.toast.show(err.message || 'Failed to create key', 'error');
      });
    });

    // Focus name input
    setTimeout(function () { nameInput.focus(); }, 100);
  }

  // -- One-time key display ---------------------------------------------------

  function showKeyResult(modalBody, result) {
    modalBody.innerHTML = '';

    // Remove the modal footer (we replace it with a Done button inside body)
    var modal = SG.modal.currentModal;
    if (modal) {
      var existingFooter = modal.querySelector('.modal-footer');
      if (existingFooter) {
        existingFooter.parentNode.removeChild(existingFooter);
      }
    }

    // Warning
    var warning = mk('div', 'key-display-warning');
    warning.innerHTML = SG.icon('alertTriangle', 16) + ' ';
    var warningText = mk('span', '');
    warningText.textContent = 'Copy this key now. It will not be shown again.';
    warning.appendChild(warningText);
    modalBody.appendChild(warning);

    // Key display
    var keyBlock = mk('div', 'key-display');
    keyBlock.textContent = result.cleartext_key || '';
    modalBody.appendChild(keyBlock);

    // Copy + Done row
    var actionRow = mk('div', 'key-result-footer');

    var copyBtn = mk('button', 'key-copy-btn');
    copyBtn.innerHTML = SG.icon('copy', 14) + ' ';
    var copyLabel = mk('span', '');
    copyLabel.textContent = 'Copy to Clipboard';
    copyBtn.appendChild(copyLabel);

    copyBtn.addEventListener('click', function () {
      var keyText = result.cleartext_key || '';
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(keyText).then(function () {
          copyBtn.classList.add('copied');
          copyLabel.textContent = 'Copied!';
          setTimeout(function () {
            copyBtn.classList.remove('copied');
            copyLabel.textContent = 'Copy to Clipboard';
          }, 2000);
        }).catch(function () {
          fallbackCopy(keyText, copyBtn, copyLabel);
        });
      } else {
        fallbackCopy(keyText, copyBtn, copyLabel);
      }
    });
    actionRow.appendChild(copyBtn);

    var doneBtn = mk('button', 'btn btn-secondary');
    doneBtn.textContent = 'Done';
    doneBtn.addEventListener('click', function () {
      SG.modal.close();
      loadData();
    });
    actionRow.appendChild(doneBtn);

    modalBody.appendChild(actionRow);

    // Info about created key
    var info = mk('div', '', {
      style: 'margin-top: var(--space-4); padding-top: var(--space-3); border-top: 1px solid var(--border);'
    });
    var infoName = mk('div', '', { style: 'font-size: var(--text-sm); color: var(--text-secondary);' });
    infoName.textContent = 'Key name: ' + (result.name || '-');
    info.appendChild(infoName);

    var infoId = mk('div', '', {
      style: 'font-size: var(--text-xs); color: var(--text-muted); margin-top: var(--space-1); font-family: var(--font-mono);'
    });
    infoId.textContent = 'ID: ' + (result.id || '-');
    info.appendChild(infoId);

    modalBody.appendChild(info);
  }

  function fallbackCopy(text, btn, label) {
    var textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.cssText = 'position:fixed;left:-9999px;top:-9999px;';
    document.body.appendChild(textarea);
    textarea.select();
    try {
      document.execCommand('copy');
      btn.classList.add('copied');
      label.textContent = 'Copied!';
      setTimeout(function () {
        btn.classList.remove('copied');
        label.textContent = 'Copy to Clipboard';
      }, 2000);
    } catch (e) {
      SG.toast.show('Failed to copy. Please select and copy manually.', 'warning');
    }
    document.body.removeChild(textarea);
  }

  function fallbackConfigCopy(text, btn, label) {
    var textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.cssText = 'position:fixed;left:-9999px;top:-9999px;';
    document.body.appendChild(textarea);
    textarea.select();
    try {
      document.execCommand('copy');
      btn.classList.add('copied');
      label.textContent = 'Copied!';
      SG.toast.show('Copied to clipboard', 'success');
      setTimeout(function () {
        btn.classList.remove('copied');
        label.textContent = 'Copy';
      }, 2000);
    } catch (e) {
      SG.toast.show('Failed to copy. Please select and copy manually.', 'warning');
    }
    document.body.removeChild(textarea);
  }

  // -- Revoke key -------------------------------------------------------------

  function revokeKey(keyId, keyName) {
    if (!confirm('Revoke API key "' + keyName + '"?\n\nThis action cannot be undone. Any client using this key will lose access.')) {
      return;
    }

    SG.api.del('/keys/' + keyId).then(function () {
      SG.toast.show('Key revoked', 'success');
      loadData();
    }).catch(function (err) {
      SG.toast.show(err.message || 'Failed to revoke key', 'error');
    });
  }

  // -- Lifecycle --------------------------------------------------------------

  function render(container) {
    cleanup();
    injectStyles();
    buildPage(container);
    loadData();
  }

  function cleanup() {
    keys = [];
    identities = [];
    identityMap = {};
    identitiesCollapsed = false;
  }

  // -- Registration -----------------------------------------------------------

  SG.router.register('access', render);
  SG.router.registerCleanup('access', cleanup);
})();
