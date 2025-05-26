function saveDraft(formData, callback) {
    fetch('/draft/create', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => callback(data))
    .catch(error => callback({ success: false, message: error.message }));
}