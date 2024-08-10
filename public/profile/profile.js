document.getElementById('profilePictureInput').addEventListener('change', async function (event) {
    const file = event.target.files[0];
    const messageElement = document.getElementById('message');

    if (!file) {
        return;
    }

    const formData = new FormData();
    formData.append('profilePicture', file);

    try {
        const response = await fetch('/api/update-profile-picture', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (response.ok) {
            document.getElementById('profileImage').src = data.profilePicture;
            messageElement.style.color = 'green';
            messageElement.textContent = data.message;
        } else {
            messageElement.style.color = 'red';
            messageElement.textContent = data.message || 'Wystąpił błąd.';
        }
    } catch (error) {
        messageElement.style.color = 'red';
        messageElement.textContent = 'Wystąpił błąd podczas aktualizacji zdjęcia profilowego.';
        console.error('Błąd:', error);
    }
});

document.getElementById('changePictureOverlay').addEventListener('click', function () {
    document.getElementById('profilePictureInput').click();
});

document.getElementById('logoutButton').addEventListener('click', async function () {
    try {
        const response = await fetch('/api/logout', {
            method: 'POST'
        });

        const data = await response.json();

        if (response.ok) {
            window.location.href = '/login';
        } else {
            alert(data.message || 'Wystąpił błąd podczas wylogowywania.');
        }
    } catch (error) {
        alert('Wystąpił błąd podczas wylogowywania.');
        console.error('Błąd:', error);
    }
});

document.addEventListener("DOMContentLoaded", () => {
    fetch('/api/get-user-info')
      .then(response => response.json())
      .then(user => {
        if (user.role === 'artist' || user.role === 'owner') {
            document.getElementById('dashboardLink').style.display = 'flex';
          }
        if (user.role === 'admin' || user.role === 'owner') {
          document.getElementById('adminPanelLink').style.display = 'block';
        }
        if (user.role === 'owner') {
          document.getElementById('ownerPanelLink').style.display = 'block';
        }
      })
      .catch(err => console.error('Błąd podczas pobierania informacji o użytkowniku:', err));
  });

  document.addEventListener('DOMContentLoaded', () => {
    const sidebar = document.querySelector('.sidebar');
    const toggleButton = document.querySelector('.toggle-button');
    const closeButton = document.querySelector('.close-button');

    toggleButton.addEventListener('click', () => {
        sidebar.classList.toggle('show');
    });

    closeButton.addEventListener('click', () => {
        sidebar.classList.remove('show');
    });
});

async function fetchUserProfile() {
    try {
        const response = await fetch('/api/user-profile');
        if (!response.ok) {
            throw new Error('Failed to fetch user profile');
        }
        const user = await response.json();

        const profileImage = document.querySelector('#profileImage');
        const sidebarProfileImage = document.querySelector('#sidebarProfileImage');
        const profileNickname = document.querySelector('.nickname');

        profileImage.src = user.profilePicture || '/uploads/profile-pics/default-profile.png';

    } catch (error) {
        console.error('Error fetching user profile:', error);
    }
}
