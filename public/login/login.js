document.getElementById('loginForm').addEventListener('submit', async function(event) {
    event.preventDefault();

    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
      });

      const result = await response.json();

      if (response.ok) {
        window.location.href = '/'; // Przekierowanie na stronę główną po zalogowaniu
      } else {
        document.getElementById('errorMessage').textContent = result.message;
      }
    } catch (error) {
      console.error('Błąd podczas próby logowania:', error);
      document.getElementById('errorMessage').textContent = 'Wystąpił błąd podczas logowania.';
    }
});
