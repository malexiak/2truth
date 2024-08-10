document.getElementById('registrationForm').addEventListener('submit', async function (event) {
    event.preventDefault();
  
    const firstName = document.getElementById('firstName').value;
    const lastName = document.getElementById('lastName').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    const nickname = document.getElementById('nickname').value;
    const birthdate = document.getElementById('birthdate').value;
  
    const response = await fetch('/api/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        firstName,
        lastName,
        email,
        password,
        confirmPassword,
        nickname,
        birthdate,
      }),
    });
  
    const result = await response.json();
    if (response.ok) {
      window.location.href = '/';
    } else {
      document.getElementById('errorMessage').textContent = result.message;
    }
  });
  