const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../server/static/js/investigation.js'), 'utf8');
function element() {
    return {
        handlers: {}, children: [], value: '', hidden: false,
        addEventListener(event, handler) { this.handlers[event] = handler; },
        setAttribute(name, value) { this[name] = value; },
        appendChild(child) { this.children.push(child); }
    };
}
const button = element();
button.hidden = true;
const sections = [true, false, false, false].map(open => Object.assign(element(), {open}));
const rows = Array.from({length: 32}, (_, i) => ({textContent: 'process-' + i + ' command', hidden: false}));
let toolbar;
const table = {tBodies: [{rows}], parentNode: {insertBefore(node) { toolbar = node; }}};
const document = {
    readyState: 'complete',
    getElementById() { return button; },
    querySelectorAll() { return sections; },
    querySelector() { return table; },
    createElement() { return element(); }
};
vm.runInNewContext(source, {document});
assert.equal(button.hidden, false);
assert.equal(button.textContent, 'Expand all');
button.handlers.click();
assert.ok(sections.every(section => section.open));
assert.equal(button.textContent, 'Collapse all');
button.handlers.click();
assert.ok(sections.every(section => !section.open));
sections.forEach(section => { section.open = true; });
sections[0].handlers.toggle();
assert.equal(button.textContent, 'Collapse all');
sections[0].open = false;
sections[0].handlers.toggle();
assert.equal(button.textContent, 'Expand all');
const [search, previous, status, next] = toolbar.children;
assert.equal(rows.filter(row => !row.hidden).length, 15);
assert.equal(previous.disabled, true);
next.handlers.click();
assert.equal(rows[0].hidden, true);
assert.equal(rows[15].hidden, false);
next.handlers.click();
assert.equal(rows.filter(row => !row.hidden).length, 2);
assert.equal(next.disabled, true);
previous.handlers.click();
assert.equal(rows[15].hidden, false);
search.value = ' PROCESS-31 ';
search.handlers.input();
assert.equal(rows.filter(row => !row.hidden).length, 1);
assert.equal(rows[31].hidden, false);
assert.equal(previous.disabled, true);
search.value = 'missing';
search.handlers.input();
assert.equal(status.textContent, 'No matching processes');
assert.ok(rows.every(row => row.hidden));
search.value = '';
search.handlers.input();
assert.equal(rows.filter(row => !row.hidden).length, 15);
// Empty pages do not require controls; pages without processes still support sections.
vm.runInNewContext(source, {document: {readyState: 'complete', getElementById() { return null; }}});
vm.runInNewContext(source, {document: {...document, querySelector() { return null; }}});
let ready;
vm.runInNewContext(source, {document: {...document, readyState: 'loading', addEventListener(event, handler) { ready = handler; }}});
assert.equal(typeof ready, 'function');
ready();
console.log('Investigation interaction checks passed');
