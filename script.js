async function searchUsers(query) {
    const response = await fetch(`/search_users?query=${encodeURIComponent(query)}`);
    const users = await response.json();
    const suggestions = document.getElementById('collaborator-suggestions');
    suggestions.innerHTML = '';
    users.forEach(user => {
        const div = document.createElement('div');
        div.textContent = user;
        div.onclick = () => {
            const collaboratorsInput = document.getElementById('collaborators');
            const currentCollaborators = collaboratorsInput.value.split(',').map(c => c.trim()).filter(c => c);
            if (!currentCollaborators.includes(user)) {
                currentCollaborators.push(user);
                collaboratorsInput.value = currentCollaborators.join(', ');
            }
            suggestions.innerHTML = '';
        };
        suggestions.appendChild(div);
    });
}