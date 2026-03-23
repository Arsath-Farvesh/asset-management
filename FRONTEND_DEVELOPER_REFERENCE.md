# Frontend Developer Quick Reference
## Takhlees Asset Management System

---

## Color Variables Quick Reference

### Brand Colors (UPDATE IMMEDIATELY)
```css
/* Primary - Government Gold */
--color-gold: #D4AF37         /* Used for primary buttons, links */
--color-accent: #D4AF37       /* Same as gold for consistency */

/* Secondary */
--color-error: #D62828        /* Errors, delete actions */
--color-success: #10b981      /* Success messages, confirmations */
--color-warning: #f59e0b      /* Warnings, cautions */
--color-info: #3b82f6         /* Information, tips */
```

### Text Colors
```css
--color-text-primary: #111827    /* Default text, dark backgrounds */
--color-text-secondary: #6c757d  /* Secondary text, descriptions */
--color-text-light: #9ca3af      /* Light text, hints */
--color-text-disabled: #d1d5db   /* Disabled inputs, inactive states */
```

### Background Colors
```css
--color-bg-default: #ffffff      /* Main background */
--color-bg-subtle: #f9fafb       /* Secondary sections */
--color-bg-muted: #f3f4f6        /* Input backgrounds, hover */
```

### Usage Examples
```html
<!-- Button (primary action) -->
<button class="btn btn-primary">Create Asset</button>

<!-- Button (secondary action) -->
<button class="btn btn-secondary">Cancel</button>

<!-- Button (danger/delete) -->
<button class="btn btn-danger">Delete</button>

<!-- Success message -->
<div class="alert alert-success">Asset created successfully!</div>

<!-- Error message -->
<div class="alert alert-danger">Error: Asset creation failed</div>

<!-- Badge/label -->
<span class="badge badge-primary">Active</span>
<span class="badge badge-success">Verified</span>
```

---

## Spacing System (8px Grid)

```css
--space-1: 8px      (0.5rem)
--space-2: 16px     (1rem)
--space-3: 24px     (1.5rem)
--space-4: 32px     (2rem)
--space-5: 40px     (2.5rem)
--space-6: 48px     (3rem)
--space-8: 64px     (4rem)
```

### Usage
```html
<!-- Margin top -->
<div class="mt-1">Margin 8px top</div>
<div class="mt-4">Margin 32px top</div>

<!-- Gap between flex items -->
<div class="d-flex gap-2">Item 1</div>
<div>Item 2</div>
```

---

## Form Field Structure Pattern

```html
<!-- Every form field should follow this pattern -->
<div class="form-group">
  <!-- Label (required) -->
  <label for="fieldId" class="form-label required-field">
    Field Label
  </label>
  
  <!-- Input with icon (optional) -->
  <div class="input-wrapper">
    <i class="input-icon bi bi-envelope"></i>
    <input 
      type="email" 
      id="fieldId" 
      name="fieldId"
      class="form-control"
      placeholder="Enter value"
      required
      aria-label="Field label"
      aria-describedby="fieldHelp fieldError"
    >
  </div>
  
  <!-- Help text (optional) -->
  <small id="fieldHelp" class="form-text text-muted">
    Help text explaining the field
  </small>
  
  <!-- Error message (appears on validation error) -->
  <div id="fieldError" class="invalid-feedback"></div>
</div>
```

---

## Button Variants

```html
<!-- Primary (main action) -->
<button class="btn btn-primary">
  <i class="bi bi-plus-circle"></i>
  Create Asset
</button>

<!-- Secondary (cancel/back) -->
<button class="btn btn-secondary">Cancel</button>

<!-- Danger (delete/destructive) -->
<button class="btn btn-danger">
  <i class="bi bi-trash"></i>
  Delete
</button>

<!-- Success (confirm) -->
<button class="btn btn-success">Confirm</button>

<!-- Outlined (less emphasis) -->
<button class="btn btn-outlined">Learn More</button>

<!-- Small -->
<button class="btn btn-primary btn-sm">
  <i class="bi bi-eye"></i>
</button>

<!-- Loading state -->
<button class="btn btn-primary loading" disabled>Loading...</button>

<!-- Disabled -->
<button class="btn btn-primary" disabled>Disabled Button</button>
```

---

## Navigation Bar Example

```html
<nav class="navbar-takhlees">
  <div class="container-fluid">
    <!-- Brand -->
    <a href="/" class="brand-logo">
      <div class="shield-icon">
        <i class="bi bi-shield-fill-check"></i>
      </div>
      <div class="brand-text">
        <span class="main">Takhlees</span>
        <span class="sub">Asset Management</span>
      </div>
    </a>
    
    <!-- Navigation Links -->
    <div class="nav-links d-flex gap-2">
      <a href="/" class="nav-btn">
        <i class="bi bi-house-fill"></i>
        <span>Home</span>
      </a>
      <a href="/history" class="nav-btn">
        <i class="bi bi-clock-history"></i>
        <span>History</span>
      </a>
    </div>
    
    <!-- User Info -->
    <div class="auth-indicator">
      <div class="user-avatar">A</div>
      <div class="user-info">
        <div class="user-name">Admin</div>
        <div class="user-role">Administrator</div>
      </div>
      <div class="auth-status"></div>
    </div>
  </div>
</nav>
```

---

## Card Component Pattern

```html
<article class="card-takhlees">
  <header class="card-header-takhlees">
    <h3>Section Title</h3>
  </header>
  
  <div class="card-body-takhlees">
    <!-- Content here -->
  </div>
</article>
```

---

## Alert Messages Pattern

```html
<!-- Success (auto-hide after 3-4s) -->
<div class="alert alert-success alert-toast" role="alert" aria-live="polite">
  <i class="bi bi-check-circle"></i>
  <div>
    <strong>Success!</strong> Asset created successfully.
  </div>
</div>

<!-- Error (stays visible) -->
<div class="alert alert-danger" role="alert">
  <i class="bi bi-exclamation-triangle"></i>
  <div>
    <strong>Error:</strong> Please fill in all required fields.
  </div>
</div>

<!-- Warning (user action required) -->
<div class="alert alert-warning" role="alert">
  <i class="bi bi-exclamation-circle"></i>
  <div>
    <strong>Warning:</strong> This action cannot be undone.
  </div>
</div>
```

---

## Form Validation JavaScript Pattern

```javascript
// Validate single field on blur
document.getElementById('email').addEventListener('blur', function(e) {
  const field = e.target;
  const errorElement = document.getElementById('emailError');
  
  const isValid = field.value && field.value.includes('@');
  
  if (!isValid) {
    field.classList.add('is-invalid');
    field.classList.remove('is-valid');
    errorElement.textContent = 'Please enter a valid email';
  } else {
    field.classList.remove('is-invalid');
    field.classList.add('is-valid');
    errorElement.textContent = '';
  }
});

// Form submission with validation
document.getElementById('myForm').addEventListener('submit', function(e) {
  e.preventDefault();
  
  // Check all required fields
  const required = this.querySelectorAll('[required]');
  let isValid = true;
  
  required.forEach(field => {
    if (!field.value.trim()) {
      field.classList.add('is-invalid');
      isValid = false;
    } else {
      field.classList.remove('is-invalid');
    }
  });
  
  if (isValid) {
    // Disable button and show loading
    const btn = this.querySelector('button[type="submit"]');
    btn.classList.add('loading');
    btn.disabled = true;
    
    // Submit form
    fetch('/api/submit', {
      method: 'POST',
      body: new FormData(this)
    })
    .then(res => res.json())
    .then(data => {
      if (data.success) {
        showAlert('Success!', 'success');
      } else {
        showAlert('Error: ' + data.error, 'danger');
      }
    })
    .finally(() => {
      btn.classList.remove('loading');
      btn.disabled = false;
    });
  }
});

// Show alert toast
function showAlert(message, type = 'info') {
  const alert = document.createElement('div');
  alert.className = `alert alert-${type} alert-toast`;
  alert.innerHTML = `<i class="bi bi-check-circle"></i><div>${message}</div>`;
  document.body.appendChild(alert);
  
  setTimeout(() => alert.remove(), 3000);
}
```

---

## Responsive Design Breakpoints

```css
/* Mobile first - default styles for mobile */
/* Then override for larger screens */

/* Small mobile: 320px */
@media (max-width: 480px) {
  /* Adjust fonts, padding, etc. */
}

/* Medium: 768px (tablet) */
@media (min-width: 768px) {
  /* Adjust layout */
}

/* Large: 1024px (desktop) */
@media (min-width: 1024px) {
  /* Full layout */
}
```

---

## Accessibility Checklist

For every form/button:

- [ ] Has `aria-label` or `aria-labelledby`
- [ ] Has `aria-describedby` pointing to help text
- [ ] Has `aria-invalid="true"` when error state
- [ ] Error message has unique `id`
- [ ] Field has `required` attribute
- [ ] Focus outline visible (handled by CSS)
- [ ] Color not the only way to convey meaning (use icons + text)

For every image/icon:
- [ ] Has `alt` attribute (can be empty for decorative: `alt=""`)
- [ ] SVG has `<title>` or `aria-label`

For every page:
- [ ] Has `<main>` tag wrapping content
- [ ] Has proper heading hierarchy (h1 → h2 → h3, etc.)
- [ ] Has skip-to-main link

---

## Common Mistakes to Avoid

❌ **DON'T:**
```html
<!-- Missing label -->
<input type="text" placeholder="Name">

<!-- Placeholder instead of label -->
<label>Name: <input type="text"></label>

<!-- Using div as button -->
<div onclick="submit()">Submit</div>

<!-- Color only indicator -->
<span style="color:red;">Required</span>

<!-- Image without alt -->
<img src="logo.png">

<!-- All caps for emphasis -->
<button>DELETE ASSET</button>
```

✅ **DO:**
```html
<!-- Proper label -->
<label for="name" class="form-label">Name</label>
<input type="text" id="name" placeholder="Enter name">

<!-- Semantic button -->
<button class="btn btn-danger">Delete Asset</button>

<!-- Proper required indicator -->
<label for="name" class="form-label required-field">Name</label>

<!-- Image with alt -->
<img src="logo.png" alt="Takhlees logo">

<!-- Icon + text for emphasis -->
<button class="btn btn-danger">
  <i class="bi bi-trash"></i>
  Delete Asset
</button>
```

---

## Testing Checklist Before Committing

- [ ] CSS loads correctly (check Network tab)
- [ ] No console errors (press F12 → Console)
- [ ] Mobile view tested (DevTools mobile mode)
- [ ] Forms validate properly
- [ ] Alerts appear and disappear correctly
- [ ] Buttons have hover/active states
- [ ] Colors match design system
- [ ] Spacing uses `--space-*` variables
- [ ] No inline styles (use CSS classes)

---

## File Structure

```
public/
├── index.html              ← Asset creation form
├── details.html            ← Asset view/edit
├── history.html            ← Asset audit trail
├── qr-scan.html            ← QR code scanner
├── login.html              ← Authentication
├── forgot-password.html    ← Password recovery
├── reset-password.html     ← Password reset
└── theme-professional.css  ← SINGLE CSS FILE (80KB max)
```

---

## CSS Update Workflow

1. **Never edit CSS inline** - Use external file only
2. **Add to theme-professional.css** - Single source of truth
3. **Use CSS variables** - for all colors, spacing, fonts
4. **Responsive mobile-first** - start with mobile styles, override for larger screens
5. **Use BEM notation** - if creating new classes:
   ```css
   /* Block */
   .asset-card { }
   
   /* Element */
   .asset-card__header { }
   
   /* Modifier */
   .asset-card--featured { }
   ```

---

## Links & Resources

- **Button Styles:** See `.btn` class in CSS
- **Form Patterns:** See FRONTEND_IMPROVEMENTS_GUIDE.md
- **Accessibility:** See WCAG 2.1 AA checklist in FRONTEND_AUDIT_REPORT.md
- **Colors:** All defined in `:root` variables
- **Breakpoints:** 480px, 768px, 1024px
- **Icons:** Bootstrap Icons library (bi-*)

---

**Last Updated:** March 8, 2026  
**Version:** 2.0 (Production Ready)
