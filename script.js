// Function to search users asynchronously and display clickable suggestions
async function searchUsers(query) {
    try {
        // Add loading animation
        const suggestions = document.getElementById('collaborator-suggestions');
        suggestions.innerHTML = '<div class="loading-spinner">🔍 Searching...</div>';
        
        const response = await fetch(`/search_users?query=${encodeURIComponent(query)}`);
        const users = await response.json();
        
        // Clear loading animation
        suggestions.innerHTML = '';
        
        // Add smooth fade-in animation for suggestions
        users.forEach((user, index) => {
            const div = document.createElement('div');
            div.className = 'suggestion';
            div.textContent = user;
            div.style.opacity = '0';
            div.style.transform = 'translateY(10px)';
            div.style.animationDelay = `${index * 50}ms`;
            
            // Add click handler with enhanced feedback
            div.onclick = () => {
                const collaboratorsInput = document.getElementById('collaborators');
                const currentCollaborators = collaboratorsInput.value.split(',').map(c => c.trim()).filter(c => c);
                
                if (!currentCollaborators.includes(user)) {
                    currentCollaborators.push(user);
                    collaboratorsInput.value = currentCollaborators.join(', ');
                    
                    // Visual feedback for successful addition
                    div.style.background = 'linear-gradient(135deg, #48bb78, #38a169)';
                    div.style.color = 'white';
                    div.style.transform = 'scale(1.05)';
                    
                    setTimeout(() => {
                        suggestions.innerHTML = '';
                    }, 300);
                } else {
                    // Visual feedback for duplicate
                    div.style.background = 'linear-gradient(135deg, #f56565, #e53e3e)';
                    div.style.color = 'white';
                    div.style.animation = 'shake 0.5s ease-in-out';
                    
                    setTimeout(() => {
                        div.style.background = '';
                        div.style.color = '';
                        div.style.animation = '';
                    }, 1000);
                }
            };
            
            // Add hover effects
            div.addEventListener('mouseenter', () => {
                div.style.transform = 'translateX(8px) scale(1.02)';
                div.style.boxShadow = '0 6px 20px rgba(102, 126, 234, 0.3)';
            });
            
            div.addEventListener('mouseleave', () => {
                div.style.transform = 'translateX(0) scale(1)';
                div.style.boxShadow = '';
            });
            
            suggestions.appendChild(div);
            
            // Animate in
            requestAnimationFrame(() => {
                div.style.transition = 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)';
                div.style.opacity = '1';
                div.style.transform = 'translateY(0)';
            });
        });
        
        // Add CSS animations if not already present
        if (!document.getElementById('suggestion-animations')) {
            const style = document.createElement('style');
            style.id = 'suggestion-animations';
            style.textContent = `
                .loading-spinner {
                    padding: 12px;
                    text-align: center;
                    opacity: 0.7;
                    animation: pulse 1.5s infinite;
                }
                
                @keyframes pulse {
                    0%, 100% { opacity: 0.7; }
                    50% { opacity: 1; }
                }
                
                @keyframes shake {
                    0%, 100% { transform: translateX(0); }
                    25% { transform: translateX(-5px); }
                    75% { transform: translateX(5px); }
                }
                
                .suggestion {
                    position: relative;
                    overflow: hidden;
                }
                
                .suggestion::before {
                    content: '';
                    position: absolute;
                    top: 0;
                    left: -100%;
                    width: 100%;
                    height: 100%;
                    background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.3), transparent);
                    transition: left 0.5s;
                }
                
                .suggestion:hover::before {
                    left: 100%;
                }
            `;
            document.head.appendChild(style);
        }
        
    } catch (error) {
        console.error('Error searching users:', error);
        const suggestions = document.getElementById('collaborator-suggestions');
        suggestions.innerHTML = '<div class="error-message">⚠️ Search failed. Please try again.</div>';
        
        // Add error styling if not present
        if (!document.getElementById('error-styles')) {
            const style = document.createElement('style');
            style.id = 'error-styles';
            style.textContent = `
                .error-message {
                    padding: 12px;
                    color: #e53e3e;
                    background: linear-gradient(135deg, rgba(255, 245, 245, 0.9) 0%, rgba(255, 235, 235, 0.9) 100%);
                    border-radius: 10px;
                    border-left: 4px solid #e53e3e;
                    text-align: center;
                    animation: fadeIn 0.3s ease-in-out;
                }
                
                @keyframes fadeIn {
                    from { opacity: 0; transform: translateY(-10px); }
                    to { opacity: 1; transform: translateY(0); }
                }
            `;
            document.head.appendChild(style);
        }
    }
}