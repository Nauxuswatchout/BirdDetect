let registeredUsername = '';
let isFormValid = {
    username: false,
    email: false,
    firstName: false,
    lastName: false,
    password: false
};

function updateSubmitButton() {
    const registerButton = document.getElementById('registerButton');
    const allValid = Object.values(isFormValid).every(value => value === true);
    console.log('Form validation status:', isFormValid);
    registerButton.disabled = !allValid;
}

function validateUsername(input) {
    const validation = document.getElementById('usernameValidation');
    const pattern = /^[a-zA-Z0-9]{8}$/;
    const value = input.value.trim();
    
    if (!value) {
        validation.textContent = 'Username is required';
        validation.className = 'validation-message error';
        isFormValid.username = false;
    } else if (!pattern.test(value)) {
        validation.textContent = 'Username must be exactly 8 characters (letters and numbers only)';
        validation.className = 'validation-message error';
        isFormValid.username = false;
    } else {
        validation.textContent = 'Username format is valid';
        validation.className = 'validation-message success';
        isFormValid.username = true;
    }
    updateSubmitButton();
}

function validateEmail(input) {
    const validation = document.getElementById('emailValidation');
    const pattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const value = input.value.trim();
    
    if (!value) {
        validation.textContent = 'Email is required';
        validation.className = 'validation-message error';
        isFormValid.email = false;
    } else if (!pattern.test(value)) {
        validation.textContent = 'Please enter a valid email address';
        validation.className = 'validation-message error';
        isFormValid.email = false;
    } else {
        validation.textContent = 'Email format is valid';
        validation.className = 'validation-message success';
        isFormValid.email = true;
    }
    updateSubmitButton();
}

function validateName(input, validationId) {
    const validation = document.getElementById(validationId);
    const pattern = /^[a-zA-Z]{2,30}$/;
    const value = input.value.trim();
    const fieldName = validationId === 'firstNameValidation' ? 'First name' : 'Last name';
    const formField = validationId === 'firstNameValidation' ? 'firstName' : 'lastName';
    
    if (!value) {
        validation.textContent = `${fieldName} is required`;
        validation.className = 'validation-message error';
        isFormValid[formField] = false;
    } else if (!pattern.test(value)) {
        validation.textContent = `${fieldName} must contain only letters (2-30 characters)`;
        validation.className = 'validation-message error';
        isFormValid[formField] = false;
    } else {
        validation.textContent = `${fieldName} is valid`;
        validation.className = 'validation-message success';
        isFormValid[formField] = true;
    }
    updateSubmitButton();
}

function validatePassword(input) {
    const requirements = {
        length: input.value.length >= 8,
        uppercase: /[A-Z]/.test(input.value),
        lowercase: /[a-z]/.test(input.value),
        number: /[0-9]/.test(input.value),
        special: /[!@#$%^&*]/.test(input.value)
    };

    // Update requirement indicators
    document.getElementById('lengthReq').className = 'requirement ' + (requirements.length ? 'met' : '');
    document.getElementById('uppercaseReq').className = 'requirement ' + (requirements.uppercase ? 'met' : '');
    document.getElementById('lowercaseReq').className = 'requirement ' + (requirements.lowercase ? 'met' : '');
    document.getElementById('numberReq').className = 'requirement ' + (requirements.number ? 'met' : '');
    document.getElementById('specialReq').className = 'requirement ' + (requirements.special ? 'met' : '');

    // Update overall password validation
    const validation = document.getElementById('passwordValidation');
    const allRequirementsMet = Object.values(requirements).every(req => req);

    if (!input.value) {
        validation.textContent = 'Password is required';
        validation.className = 'validation-message error';
        isFormValid.password = false;
    } else if (!allRequirementsMet) {
        validation.textContent = 'Please meet all password requirements';
        validation.className = 'validation-message error';
        isFormValid.password = false;
    } else {
        validation.textContent = 'Password meets all requirements';
        validation.className = 'validation-message success';
        isFormValid.password = true;
    }
    updateSubmitButton();
}

async function handleRegister(event) {
    event.preventDefault();
    console.log('Starting registration process...');

    // Get form elements directly from the form
    const form = document.getElementById('signupForm');
    const formData = {
        username: form.querySelector('#username').value.trim(),
        email: form.querySelector('#email').value.trim(),
        firstName: form.querySelector('#firstName').value.trim(),
        lastName: form.querySelector('#lastName').value.trim(),
        password: form.querySelector('#password').value
    };

    // Log form data (excluding password)
    console.log('Form data:', {
        ...formData,
        password: '[REDACTED]'
    });

    // Validate all fields are filled
    for (const [key, value] of Object.entries(formData)) {
        if (!value) {
            console.log(`Missing field: ${key}`);
            alert(`${key} is required`);
            return;
        }
    }

    const loading = document.querySelector('#registerForm .loading');
    const submitButton = document.querySelector('#registerForm .submit-button');

    try {
        loading.classList.add('active');
        submitButton.disabled = true;
        console.log('Sending registration request...');

        const response = await fetch('/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(formData)
        });

        console.log('Response status:', response.status);
        const data = await response.json();
        console.log('Response data:', data);

        if (data.status === 'success') {
            registeredUsername = formData.username;
            document.getElementById('registerForm').style.display = 'none';
            document.getElementById('confirmationForm').style.display = 'block';
        } else {
            alert(data.message || 'Registration failed. Please check your input and try again.');
        }
    } catch (error) {
        console.error('Registration error:', error);
        alert('Registration failed. Please check the console for more details.');
    } finally {
        loading.classList.remove('active');
        submitButton.disabled = false;
    }
}

async function handleConfirmation() {
    const code = document.getElementById('confirmationCode').value.trim();
    const loading = document.querySelector('#confirmationForm .loading');
    const submitButton = document.querySelector('#confirmationForm .submit-button');

    if (!code) {
        alert('Please enter the verification code');
        return;
    }

    if (!registeredUsername) {
        console.error('No username found for confirmation');
        alert('Registration session expired. Please register again.');
        window.location.href = '/register';
        return;
    }

    console.log('Starting confirmation process...');
    console.log('Confirmation data:', {
        username: registeredUsername,
        code: code,
        codeLength: code.length
    });

    loading.classList.add('active');
    submitButton.disabled = true;

    try {
        console.log('Sending confirmation request...');
        const response = await fetch('/confirm-signup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                username: registeredUsername,
                code: code
            })
        });

        console.log('Confirmation response status:', response.status);
        const data = await response.json();
        console.log('Confirmation response data:', data);

        if (response.ok && data.status === 'success') {
            // If we received tokens, store them
            if (data.tokens) {
                console.log('Storing authentication tokens...');
                localStorage.setItem('access_token', data.tokens.access_token);
                localStorage.setItem('id_token', data.tokens.id_token);
                localStorage.setItem('refresh_token', data.tokens.refresh_token);
                console.log('Tokens stored successfully');
            }
            
            alert(data.message);
            
            // Redirect to appropriate page
            window.location.href = data.tokens ? '/' : '/login';
        } else {
            console.error('Confirmation failed:', data);
            alert(data.message || 'Verification failed. Please try again.');
        }
    } catch (error) {
        console.error('Confirmation error:', error);
        alert('Verification failed. Please check the console for more details.');
    } finally {
        loading.classList.remove('active');
        submitButton.disabled = false;
    }
}

// Initialize form validation when the document is loaded
document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('signupForm');
    if (form) {
        form.addEventListener('submit', handleRegister);
        
        // Initial validation of all fields
        validateUsername(document.getElementById('username'));
        validateEmail(document.getElementById('email'));
        validateName(document.getElementById('firstName'), 'firstNameValidation');
        validateName(document.getElementById('lastName'), 'lastNameValidation');
        validatePassword(document.getElementById('password'));
    }
}); 