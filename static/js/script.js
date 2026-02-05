document.addEventListener('DOMContentLoaded', () => {
    const input = document.getElementById('input');
    const send = document.getElementById('send');
    const messages = document.getElementById('messages');
    const historyList = document.getElementById('history-list');

    send.addEventListener('click', sendMessage);
    input.addEventListener('keypress', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });

    // 加载当前用户的历史（隔离）
    fetch('/history')
        .then(res => {
            if (!res.ok) throw new Error('Failed to load history');
            return res.json();
        })
        .then(data => {
            data.forEach(item => {
                addMessage(item.role, item.content);
                // 更新历史列表（用时间戳或内容摘要作为项）
                const li = document.createElement('li');
                li.textContent = `${item.timestamp}: ${item.content.substring(0, 20)}...`;
                historyList.appendChild(li);
            });
        })
        .catch(err => console.error(err));

    function sendMessage() {
        const msg = input.value.trim();
        if (!msg) return;

        // 添加用户消息
        addMessage('user', msg);
        input.value = '';

        // 发送到后端代理
        fetch('/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: msg })
        }).then(response => {
            if (!response.ok) throw new Error('Chat error');
            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let assistantMsg = '';
            const assistantDiv = addMessage('assistant', ''); // 占位

            function readChunk() {
                reader.read().then(({ done, value }) => {
                    if (done) {
                        // 更新历史列表（可选）
                        const li = document.createElement('li');
                        li.textContent = `Now: ${assistantMsg.substring(0, 20)}...`;
                        historyList.appendChild(li);
                        return;
                    }
                    const chunk = decoder.decode(value);
                    assistantMsg += chunk;
                    // 流式更新（typing effect）
                    assistantDiv.innerHTML = marked.parse(assistantMsg); // Markdown 渲染
                    readChunk();
                });
            }
            readChunk();
        }).catch(err => console.error(err));
    }

    function addMessage(role, content) {
        const div = document.createElement('div');
        div.classList.add('message', role);
        div.innerHTML = marked.parse(content); // Markdown
        messages.appendChild(div);
        messages.scrollTop = messages.scrollHeight;
        return div;
    }
});