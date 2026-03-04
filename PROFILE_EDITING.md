# User Profile Editing Feature

## Overview
Users can now click their authentication indicator (username badge in navbar) to open a profile editing modal where they can update their email, department, and password.

## How to Use

### Opening the Profile Modal
1. Click on the user profile indicator in the top-right corner of the navbar (shows avatar and username)
2. The profile modal will slide down with a smooth animation

### Viewing Profile
- The modal displays:
  - User avatar (first letter of username in gold gradient circle)
  - Full username
  - User role (Admin/User)
  - Current email address
  - Current department

### Editing Profile
1. Click the "Edit Profile" button
2. Form fields appear for:
   - **Email Field**: Edit email address (validates proper format)
   - **Department Field**: Edit department or role
   - **Password Field**: Leave blank to keep current password (optional)
   - **Confirm Password Field**: Must match password field if changing password

### Saving Changes
1. Fill in the fields you want to update
2. Click "Save Changes"
3. System validates:
   - Email format is valid
   - Password is at least 8 characters if provided
   - Passwords match (if changing password)
4. On success: Green success message appears, profile updates after 1.5 seconds
5. On error: Red error message displays (e.g., email already in use, weak password)

### Canceling Changes
- Click "Cancel" button to discard unsaved changes
- Click "Close" button or click outside the modal overlay to close without saving

## Technical Implementation

### Frontend Files Modified
- **public/index.html**: Added profile modal CSS, HTML, and JavaScript
- **public/details.html**: Added profile modal CSS, HTML, and JavaScript  
- **public/history.html**: Added profile modal CSS and JavaScript
- **public/qr-scan.html**: Added profile modal CSS and JavaScript

### Backend Changes
- **server.js**: Added `PUT /api/user/profile` endpoint
  - Location: Lines 551-620
  - Validates email format and uniqueness
  - Validates password strength (8+ chars with requirements)
  - Hashes new password with bcrypt
  - Updates users table with new email/department/password
  - Returns updated user object

### Database Schema
The users table already includes these columns (no migration needed):
```sql
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  email TEXT,
  department TEXT,
  password TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  ...
)
```

## Styling & Design

### Modal UI Components
- **Profile Modal Overlay**: Fixed position, semi-transparent dark background, z-index 1000
- **Profile Modal Container**: White rounded card (16px border-radius) with slideDown animation
- **Profile Header**: Gradient background (dark navy), contains:
  - Large avatar circle (80px, gold gradient)
  - Username and role display
- **Profile Body**: Contains form fields and info display
- **Profile Fields**: Clean label-value pairs
- **Input Fields**: 
  - 2px border, focus state shows gold border + shadow
  - 0.75rem padding, 1rem font size
  - Full width, responsive
- **Buttons**:
  - Save (Green #10b981)
  - Cancel (Gray #e5e7eb)
  - Close (Red #ef4444)
  - Edit (Gray #6b7280)
  - All buttons have hover opacity effect

### Responsive Design
- Modal width: 90% on mobile, max 500px desktop
- Buttons stack in flex row with 0.75rem gap
- Works seamlessly on phones, tablets, and desktops

## Animations
- Modal entrance: slideDown animation (300ms ease)
  - Starts: opacity 0, translateY(-50px)
  - Ends: opacity 1, translateY(0)

## Error Handling
- Invalid email format: Shows error message
- Email already in use: Shows error message
- Password mismatch: Shows error message
- Password too weak: Shows requirement message
- Network errors: Shows generic error message with error text

## Security Features
- ✅ Passwords hashed with bcrypt (10 rounds)
- ✅ HTTPS-only cookies in production
- ✅ Session validation required
- ✅ Email uniqueness enforcement
- ✅ Password strength validation (8+ chars, uppercase, lowercase, number, special)
- ✅ SQL injection prevention (parameterized queries)
- ✅ CSRF protection via session

## API Endpoint

### PUT /api/user/profile
**Description**: Update authenticated user's profile

**Request Body**:
```json
{
  "email": "newemail@example.com",
  "department": "New Department",
  "password": "newPassword@123"  // optional - leave out to keep current password
}
```

**Response (Success - 200)**:
```json
{
  "success": true,
  "user": {
    "id": 1,
    "username": "admin",
    "email": "newemail@example.com",
    "role": "admin",
    "department": "New Department"
  },
  "message": "Profile updated successfully"
}
```

**Response (Error)**:
```json
{
  "success": false,
  "error": "Email already in use"
}
```

**Error Codes**:
- 401: Not authenticated
- 400: Validation error (invalid email, weak password, email taken)
- 500: Server error

## Testing Checklist
- [ ] Login with admin user
- [ ] Click auth indicator (should open profile modal)
- [ ] View current profile info (email, department)
- [ ] Click "Edit Profile" button
- [ ] Update email to valid format
- [ ] Update department field
- [ ] Click "Save Changes"
- [ ] Verify success message appears
- [ ] Verify modal closes after success
- [ ] Refresh page and verify changes persisted
- [ ] Test password change with confirmation
- [ ] Test invalid email format (shows error)
- [ ] Test password mismatch (shows error)
- [ ] Test short password (shows error)
- [ ] Test duplicate email (shows error)
- [ ] Test clicking outside modal (closes)
- [ ] Test Cancel button (returns to view mode)
- [ ] Test on mobile device (responsive)

## Files Changed
1. `/server.js` - Added PUT /api/user/profile endpoint
2. `/public/index.html` - Added profile modal CSS, HTML, JavaScript
3. `/public/details.html` - Added profile modal CSS, HTML, JavaScript
4. `/public/history.html` - Added profile modal CSS and JavaScript
5. `/public/qr-scan.html` - Added profile modal CSS and JavaScript

## Commit Information
- **Commit Hash**: d60f2aa
- **Message**: "Add user profile editing modal across all pages"
- **Date**: Latest commit
- **Files Modified**: 5
- **Lines Added**: ~600+

## Future Enhancements
- [ ] Avatar/profile picture upload
- [ ] Two-factor authentication setup in profile
- [ ] Login history/device management
- [ ] Session timeout customization
- [ ] Email verification when changing email
- [ ] Password change email notification
- [ ] Biometric login setup (fingerprint, face ID)
