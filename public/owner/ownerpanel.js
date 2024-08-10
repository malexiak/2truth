async function fetchUserProfile() {
    try {
        const response = await fetch('/api/user-profile');
        if (!response.ok) {
            throw new Error('Failed to fetch user profile');
        }
        const user = await response.json();

        const profileImage = document.querySelector('#profileImage');
        const profileNickname = document.querySelector('.nickname');

        profileImage.src = user.profileImageUrl || '/uploads/profile-pics/default-profile.png';
        profileNickname.textContent = user.nickname || 'Username';
    } catch (error) {
        console.error('Error fetching user profile:', error);
    }
}

async function fetchUsers(query = '') {
    const response = await fetch(`/api/all-users?query=${encodeURIComponent(query)}`);
    const users = await response.json();

    const usersContainer = document.querySelector('#usersContainer');
    usersContainer.innerHTML = '';

    users.forEach(user => {
        const userCard = document.createElement('div');
        userCard.classList.add('user-card');

        const profileImage = document.createElement('img');
        profileImage.src = user.profileImageUrl || '/uploads/profile-pics/default-profile.png';
        profileImage.alt = `${user.nickname}'s profile picture`;
        profileImage.classList.add('profile-image');
        userCard.appendChild(profileImage);

        const fullName = document.createElement('h3');
        fullName.textContent = `${user.firstName} ${user.lastName}`;
        userCard.appendChild(fullName);

        const nickname = document.createElement('p');
        nickname.textContent = `${user.nickname}`;
        userCard.appendChild(nickname);

        const email = document.createElement('p');
        email.textContent = `${user.email}`;
        userCard.appendChild(email);

        const roleSelect = document.createElement('select');
        ['owner', 'admin', 'artist', 'user'].forEach(role => {
            const option = document.createElement('option');
            option.value = role;
            option.textContent = role;
            if (role === user.role) {
                option.selected = true;
            }
            roleSelect.appendChild(option);
        });
        userCard.appendChild(roleSelect);

        userCard.dataset.userId = user.id;
        usersContainer.appendChild(userCard);
    });
}

async function saveChanges() {
    const userCards = document.querySelectorAll('.user-card');
    for (const card of userCards) {
        const userId = card.dataset.userId;
        const newRole = card.querySelector('select').value;

        try {
            const response = await fetch('/api/update-user-role', {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ userId, newRole }),
            });
            
            if (!response.ok) {
                throw new Error('Błąd podczas aktualizacji roli użytkownika');
            }
        } catch (error) {
            console.error(`Błąd dla użytkownika ID ${userId}:`, error);
            showNotification('Wystąpił błąd podczas zapisywania zmian.');
        }
    }
    showNotification('Zmiany zostały zapisane.');
}


function showNotification(message) {
    const notification = document.querySelector('#notification');
    notification.textContent = message;
    notification.classList.add('show');
    setTimeout(() => {
        notification.classList.remove('show');
    }, 3000);
}

document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.querySelector('#searchInput');
    const saveButton = document.querySelector('#saveButton');

    searchInput.addEventListener('input', () => {
        fetchUsers(searchInput.value);
    });

    saveButton.addEventListener('click', saveChanges);

    fetchUsers();
    fetchUserProfile();

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
