// Debug: Check if script is loading
console.log('🔧 Iframe test script loaded!');

// Check if we can even run JavaScript
function checkJavaScriptEnabled() {
    try {
        // This will only execute if JavaScript is enabled
        document.getElementById('parent-origin-test').textContent = '🔄 Testing...';
        console.log('🔧 JavaScript is enabled and running');
        return true;
    } catch (e) {
        console.log('🔧 JavaScript error:', e);
        // If we can't even access DOM, JavaScript is disabled
        console.log('🔧 JavaScript appears to be disabled');
        return false;
    }
}

// Check if JavaScript is enabled before proceeding
if (!checkJavaScriptEnabled()) {
    console.log('🔧 Stopping execution - JavaScript disabled');
} else {
    console.log('🔧 JavaScript enabled, continuing with tests');
}

// Random word generation for postMessage tests
const adjectives = ['pesky', 'sneaky', 'clever', 'brave', 'curious', 'mysterious', 'friendly', 'swift', 'wise', 'gentle'];
const nouns = ['penguin', 'dragon', 'wizard', 'knight', 'explorer', 'detective', 'artist', 'scientist', 'hero', 'traveler'];

function getRandomMessage() {
    const adj = adjectives[Math.floor(Math.random() * adjectives.length)];
    const noun = nouns[Math.floor(Math.random() * nouns.length)];
    return `${adj} ${noun}`;
}

// Set origin info with error handling - only update if JavaScript is running
document.getElementById('iframe-origin').textContent = window.location.origin;
try {
    document.getElementById('parent-origin').textContent = window.parent.location.origin;
    document.getElementById('same-origin').textContent = window.location.origin === window.parent.location.origin ? 'YES' : 'NO';
} catch (e) {
    document.getElementById('parent-origin').textContent = 'BLOCKED';
    document.getElementById('same-origin').textContent = 'UNKNOWN';
    console.log('🔧 Cannot access parent origin:', e.name + ': ' + e.message);
}

// Auto-run all tests when JavaScript is available
function runAllTests() {
    console.log('🔧 JavaScript is enabled, running tests...');
    
    // Update all test statuses to "Testing..."
    const testElements = [
        'parent-cookie-test', 'parent-localstorage-test', 'navigation-test', 'postmessage-test',
        'inline-script-test', 'event-handler-test',
        'same-origin-cookie-test', 'same-origin-storage-test', 'same-origin-origin-test'
    ];
    
    testElements.forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = '🔄 Testing...';
            element.className = 'testing';
        }
    });
    
    // Run tests asynchronously with proper error isolation
    const tests = [
        () => testParentCookie(),
        () => testParentLocalStorage(),
        () => testNavigation(),
        () => testPostMessage(),
        () => testInlineScript(),
        () => testEventHandler(),
        () => testSameOriginEffects()
    ];
    
    // Run each test independently with delays
    tests.forEach((test, index) => {
        setTimeout(() => {
            try {
                test();
            } catch (e) {
                console.log('🔧 Test failed with uncaught error:', e);
            }
        }, (index + 1) * 100);
    });
}

// Helper function to set error message with truncation
function setErrorMessage(elementId, message) {
    const element = document.getElementById(elementId);
    const maxLength = 25;
    
    // Store the full message as a data attribute
    element.setAttribute('data-full-message', message);
    
    // Truncate the message if it's too long
    if (message.length > maxLength) {
        element.textContent = message.substring(0, maxLength) + '...';
        element.className = 'failure truncatable';
        
        // Add click handler to expand (one-time only)
        element.onclick = function() {
            this.textContent = this.getAttribute('data-full-message');
            this.className = 'failure';
            this.onclick = null; // Remove click handler
        };
    } else {
        element.textContent = message;
        element.className = 'failure';
    }
}



function testParentCookie() {
    try {
        const cookies = window.parent.document.cookie;
        if (cookies === null || cookies === undefined) {
            document.getElementById('parent-cookie-test').textContent = '❌ null/undefined';
            document.getElementById('parent-cookie-test').className = 'failure';
        } else {
            const hasSecret = cookies.includes('secret=');
            document.getElementById('parent-cookie-test').textContent = hasSecret ? '✅ SECRET FOUND!' : '✅ "' + cookies.substring(0, 20) + '..."';
            document.getElementById('parent-cookie-test').className = 'success';
        }
    } catch (e) {
        setErrorMessage('parent-cookie-test', '❌ ' + e.name + ': ' + e.message);
    }
}

function testParentLocalStorage() {
    try {
        const secret = window.parent.localStorage.getItem('secretKey');
        if (secret === null || secret === undefined) {
            document.getElementById('parent-localstorage-test').textContent = '❌ null/undefined';
            document.getElementById('parent-localstorage-test').className = 'failure';
        } else {
            document.getElementById('parent-localstorage-test').textContent = '✅ SECRET FOUND: "' + secret + '"';
            document.getElementById('parent-localstorage-test').className = 'success';
        }
    } catch (e) {
        setErrorMessage('parent-localstorage-test', '❌ ' + e.name + ': ' + e.message);
    }
}

function testNavigation() {
    try {
        // Just test if we can access the property, don't actually navigate
        const href = window.parent.location.href;
        if (href === null || href === undefined) {
            document.getElementById('navigation-test').textContent = '❌ null/undefined';
            document.getElementById('navigation-test').className = 'failure';
        } else {
            document.getElementById('navigation-test').textContent = '✅ Can access: "' + href.substring(0, 30) + '..."';
            document.getElementById('navigation-test').className = 'success';
        }
    } catch (e) {
        setErrorMessage('navigation-test', '❌ ' + e.name + ': ' + e.message);
    }
}

function testPostMessage() {
    try {
        const randomMessage = getRandomMessage();
        window.parent.postMessage({
            type: 'iframe-message', 
            message: randomMessage,
            iframeId: window.location.hash || 'unknown'
        }, '*');
        document.getElementById('postmessage-test').textContent = '✅ Sent: "' + randomMessage + '"';
        document.getElementById('postmessage-test').className = 'success';
    } catch (e) {
        setErrorMessage('postmessage-test', '❌ ' + e.name + ': ' + e.message);
    }
}



function testSameOriginEffects() {
    try {
        // Test if we can access our own cookies (this is what allow-same-origin affects)
        document.cookie = 'iframe-test-cookie=test-value; path=/';
        const cookieValue = document.cookie.split('; ').find(row => row.startsWith('iframe-test-cookie='));
        const hasCookie = cookieValue && cookieValue.split('=')[1] === 'test-value';
        
        document.getElementById('same-origin-cookie-test').textContent = hasCookie ? '✅ Can access own cookies' : '❌ Cannot access own cookies';
        document.getElementById('same-origin-cookie-test').className = hasCookie ? 'success' : 'failure';
    } catch (e) {
        setErrorMessage('same-origin-cookie-test', '❌ ' + e.name + ': ' + e.message);
    }
    
    try {
        // Test if we can access our own localStorage
        localStorage.setItem('iframe-test-key', 'test-value');
        const storedValue = localStorage.getItem('iframe-test-key');
        const hasStorage = storedValue === 'test-value';
        
        document.getElementById('same-origin-storage-test').textContent = hasStorage ? '✅ Can access own localStorage' : '❌ Cannot access own localStorage';
        document.getElementById('same-origin-storage-test').className = hasStorage ? 'success' : 'failure';
    } catch (e) {
        setErrorMessage('same-origin-storage-test', '❌ ' + e.name + ': ' + e.message);
    }
    
    try {
        // Test if we can access our own origin
        const ownOrigin = window.location.origin;
        const hasOrigin = ownOrigin && ownOrigin !== 'null';
        
        document.getElementById('same-origin-origin-test').textContent = hasOrigin ? `✅ Own origin: ${ownOrigin}` : '❌ No origin (opaque)';
        document.getElementById('same-origin-origin-test').className = hasOrigin ? 'success' : 'failure';
    } catch (e) {
        setErrorMessage('same-origin-origin-test', '❌ ' + e.name + ': ' + e.message);
    }
}

function testInlineScript() {
    try {
        // Test if inline scripts are executed
        const script = document.createElement('script');
        script.textContent = 'window.inlineScriptTest = "executed";';
        document.head.appendChild(script);
        const result = window.inlineScriptTest === 'executed';
        document.getElementById('inline-script-test').textContent = result ? '✅ Inline script executed' : '❌ Inline script blocked';
        document.getElementById('inline-script-test').className = result ? 'success' : 'failure';
        document.head.removeChild(script);
    } catch (e) {
        setErrorMessage('inline-script-test', '❌ ' + e.name + ': ' + e.message);
    }
}

function testEventHandler() {
    try {
        // Test if event handlers work
        const button = document.createElement('button');
        button.onclick = function() { window.eventHandlerTest = 'clicked'; };
        button.click();
        const result = window.eventHandlerTest === 'clicked';
        document.getElementById('event-handler-test').textContent = result ? '✅ Event handler executed' : '❌ Event handler blocked';
        document.getElementById('event-handler-test').className = result ? 'success' : 'failure';
    } catch (e) {
        setErrorMessage('event-handler-test', '❌ ' + e.name + ': ' + e.message);
    }
}



// Listen for messages from parent
window.addEventListener('message', function(event) {
    document.getElementById('message-received').textContent = '✅ ' + JSON.stringify(event.data);
    document.getElementById('message-received').className = 'success';
});

// Auto-run all tests when page loads
console.log('🔧 About to run all tests...');
runAllTests();

// Notify parent that we're ready to receive messages (like WebLab2 does)
setTimeout(() => {
    try {
        window.parent.postMessage({
            type: 'iframe-ready',
            origin: window.location.origin,
            timestamp: new Date().toISOString()
        }, '*');
        console.log('🔧 Sent iframe-ready message to parent');
    } catch (e) {
        console.log('🔧 Could not send iframe-ready message:', e);
    }
}, 100);

// Console functions for manual testing
window.testAll = function() {
    console.log('🧪 Running all iframe tests...');
    testParentCookie();
    testParentLocalStorage();
    testNavigation();
    testPostMessage();
    testInlineScript();
    testEventHandler();
    testSameOriginEffects();
};
