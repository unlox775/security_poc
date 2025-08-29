// Debug: Check if parent script is loading
console.log('🔧 Parent script loaded!');

// Set up parent page
document.getElementById('parent-origin').textContent = window.location.origin;
document.getElementById('secret-cookie').textContent = 'super-secret-cookie-value-12345';
document.getElementById('localstorage-key').textContent = 'secret-localstorage-value-67890';

// Detect if we're on child origin and update title
const isChildOrigin = window.location.hostname.includes('child-site.local');
const originInfo = isChildOrigin ? 
    '(🔄 Child Origin - Testing same-origin behavior. <a href="http://parent-site.local:8080">Switch to Parent</a>)' : 
    '(🏠 Parent Origin - Testing cross-origin iframes from child-site.local. <a href="http://child-site.local:8080">Switch to Child</a>)';
document.getElementById('origin-info').innerHTML = originInfo;

// Set secret cookie and localStorage
document.cookie = 'secret=super-secret-cookie-value-12345; path=/';
localStorage.setItem('secretKey', 'secret-localstorage-value-67890');

// Track which iframes are ready
const readyIframes = new Set();
const totalIframes = 4; // We have 4 iframes

// Fallback: Send messages after 5 seconds if not all iframes are ready
setTimeout(() => {
    if (readyIframes.size < totalIframes) {
        console.log('🔧 Fallback: Sending messages to iframes after timeout');
        sendMessagesToAllIframes();
    }
}, 5000);

// Function to send messages to all iframes
function sendMessagesToAllIframes() {
    const iframes = document.querySelectorAll('iframe');
    iframes.forEach((iframe, index) => {
        setTimeout(() => {
            try {
                iframe.contentWindow.postMessage({
                    type: 'parent-message',
                    message: `Hello from parent to iframe ${index + 1}!`,
                    timestamp: new Date().toISOString()
                }, '*');
                console.log('🔧 Sent message to iframe', index + 1);
            } catch (e) {
                console.log('🔧 Could not send message to iframe:', e);
            }
        }, index * 200); // Longer delay between messages
    });
}

// Listen for messages from iframes
window.addEventListener('message', function(event) {
    console.log('Parent received message:', event);
    
    // Handle iframe ready messages
    if (event.data.type === 'iframe-ready') {
        readyIframes.add(event.origin || 'unknown');
        console.log('🔧 Iframe ready:', event.origin, `(${readyIframes.size}/${totalIframes})`);
        
        // Send messages to all iframes when ALL iframes are ready
        if (readyIframes.size === totalIframes) {
            console.log('🔧 All iframes ready! Sending messages...');
            setTimeout(() => {
                sendMessagesToAllIframes();
            }, 1000); // Wait 1 second after all iframes are ready
        }
        return;
    }
    
    const resultsDiv = document.getElementById('test-results');
    const resultDiv = document.createElement('div');
    resultDiv.className = 'results';
    
    let status = 'success';
    if (event.data.error) status = 'failure';
    if (event.data.warning) status = 'warning';
    
    let messageText = event.data.message;
    if (event.data.type === 'iframe-message') {
        messageText = `Message from iframe: "${event.data.message}"`;
    }
    
    resultDiv.innerHTML = `
        <strong class="${status}">${event.data.type || 'Message'}:</strong> 
        ${messageText}
        <br><small>Origin: ${event.origin}</small>
    `;
    
    resultsDiv.appendChild(resultDiv);
});




