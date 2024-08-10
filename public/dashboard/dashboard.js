async function fetchUsers(query = '') {
    try {
        const response = await fetch(`/api/users?query=${encodeURIComponent(query)}`);
        const users = await response.json();

        const userList = document.getElementById('userList');
        userList.innerHTML = '';

        if (users.length === 0) {
            userList.innerHTML = '<li>Brak użytkowników</li>';
        } else {
            users.forEach(user => {
                const listItem = document.createElement('li');
                listItem.textContent = `${user.firstName} ${user.lastName} (${user.nickname}, ${user.email}) - Rola: ${user.role}`;
                userList.appendChild(listItem);
            });
        }
    } catch (error) {
        console.error('Błąd podczas pobierania użytkowników:', error);
    }
}

window.onload = () => {
    fetchUsers();
};

const searchInput = document.getElementById('searchQuery');
searchInput.addEventListener('input', () => {
    const query = searchInput.value;
    fetchUsers(query);
});