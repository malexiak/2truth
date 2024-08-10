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

    fetchUserProfile();
});

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
