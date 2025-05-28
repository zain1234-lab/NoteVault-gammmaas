// Function to save draft data to the server with a callback for response handling
function saveDraft(formData, callback) {
    // Create and show loading indicator
    const loadingIndicator = createLoadingIndicator();
    document.body.appendChild(loadingIndicator);
    
    // Add visual feedback to the save button if it exists
    const saveButton = document.querySelector('[type="submit"], .save-button, .button');
    const originalButtonText = saveButton ? saveButton.textContent : '';
    const originalButtonStyle = saveButton ? saveButton.style.cssText : '';
    
    if (saveButton) {
        saveButton.textContent = '💾 Saving...';
        saveButton.style.background = 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)';
        saveButton.style.animation = 'pulse 1.5s infinite';
        saveButton.disabled = true;
    }
    
    fetch('/draft/create', {
        method: 'POST',
        body: formData
    })
    .then(response => {
        // Add response status visual feedback
        if (response.ok) {
            showStatusFeedback('success', '✅ Draft saved successfully!');
        } else {
            showStatusFeedback('error', '❌ Failed to save draft');
        }
        return response.json();
    })
    .then(data => {
        // Enhanced success/error handling with visual feedback
        if (data.success) {
            showSuccessAnimation();
            if (saveButton) {
                saveButton.textContent = '✅ Saved!';
                saveButton.style.background = 'linear-gradient(135deg, #48bb78 0%, #38a169 100%)';
                saveButton.style.animation = 'successPulse 0.6s ease-in-out';
            }
        } else {
            showErrorAnimation();
            if (saveButton) {
                saveButton.textContent = '❌ Failed';
                saveButton.style