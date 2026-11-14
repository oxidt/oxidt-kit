import { test, expect } from '@playwright/test';

const field = page => page.locator('.cm-content').first();
const source = page => page.locator('#body');
async function write(page, text) {
    await field(page).focus();
    await page.keyboard.press('ControlOrMeta+a');
    await page.keyboard.insertText(text);
}

test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await expect(field(page)).toBeVisible();
});

test('typing formats in place and preserves Markdown in the form', async ({ page }) => {
    await write(page, '## Heading\n\n**Bold** and *italic*\n\n- first');
    await page.keyboard.press('End');
    await page.keyboard.press('Enter');
    await expect(source(page)).toHaveValue('## Heading\n\n**Bold** and *italic*\n\n- first\n- ');
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(page.locator('.md-h2')).toHaveText('Heading');
    await expect(page.locator('.md-strong')).toHaveText('Bold');
    expect(await page.evaluate(() => new FormData(document.querySelector('form')).get('body'))).toContain('**Bold**');
});

test('controlled values update without an input echo', async ({ page }) => {
    await source(page).evaluate(el => { el.value = '# Restored'; });
    await expect(source(page)).toHaveValue('# Restored');
    await expect(page.locator('.md-h1')).toHaveText('Restored');
    expect(await page.evaluate(() => window.inputs)).toBe(0);
    await field(page).focus();
    await expect(page.locator('.md-h1')).toHaveText('# Restored');
});

test('a value rewritten during input, as a rejected controlled edit, reaches the editor', async ({ page }) => {
    await source(page).evaluate(el => el.addEventListener('input', () => { el.value = el.value.toUpperCase(); }));
    await write(page, 'shout');
    await expect(source(page)).toHaveValue('SHOUT');
    await expect(field(page)).toHaveText('SHOUT');
});

test('image insertion is an independent undo step', async ({ page }) => {
    await write(page, 'Before');
    expect(await page.locator('oxidt-markdown-editor').evaluate(el => el.editor.insert(6, '\n\n![image](image.png)'))).toBe(true);
    await expect(source(page)).toHaveValue('Before\n\n![image](image.png)');
    await page.keyboard.press('ControlOrMeta+z');
    await expect(source(page)).toHaveValue('Before');
});

test('disabled state, maxlength, labels, and required validation work', async ({ page }) => {
    await source(page).evaluate(el => { el.disabled = true; });
    await expect(field(page)).toHaveAttribute('contenteditable', 'false');
    await source(page).evaluate(el => { el.disabled = false; el.maxLength = 5; });
    await write(page, 'hello');
    await page.keyboard.insertText('!');
    await expect(source(page)).toHaveValue('hello');
    expect(await page.locator('oxidt-markdown-editor').evaluate(el => el.editor.insert(5, '!'))).toBe(false);
    await expect(source(page)).toHaveValue('hello');
    await write(page, '');
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(field(page)).toBeFocused();
    expect(await page.evaluate(() => window.submits)).toBe(0);
    await page.getByRole('button', { name: 'Reset', exact: true }).focus();
    await page.locator('label').click();
    await expect(field(page)).toBeFocused();
});

test('form reset restores the original source and visible editor', async ({ page }) => {
    await write(page, '# Changed');
    await page.getByRole('button', { name: 'Reset', exact: true }).click();
    await expect(source(page)).toHaveValue('# Original\n\n**Text**');
    await expect(page.locator('.md-h1')).toHaveText('Original');
});

test('remounting cleans up the view and fields stay independent', async ({ page }) => {
    await page.evaluate(() => {
        const other = document.createElement('oxidt-markdown-editor');
        other.innerHTML = '<div data-editor-host></div><textarea aria-label="Other">Other</textarea>';
        document.body.append(other);
        window.detached = document.querySelector('oxidt-markdown-editor');
        window.detached.remove();
    });
    await expect.poll(() => page.evaluate(() => window.detached.editor)).toBeNull();
    await page.evaluate(() => document.querySelector('form').prepend(window.detached));
    await expect(page.locator('.cm-editor')).toHaveCount(2);
    await write(page, 'Independent');
    await expect(page.locator('textarea[aria-label="Other"]')).toHaveValue('Other');
    await expect(source(page)).toHaveValue('Independent');
});

test('without the module, the textarea remains a working form field', async ({ page }) => {
    await page.goto('/?fallback=1');
    await expect(source(page)).toBeVisible();
    await source(page).fill('Plain Markdown');
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    expect(await page.evaluate(() => window.submits)).toBe(1);
});

for (const [command, markdown] of [
    ['heading-1', '# '], ['heading-2', '## '], ['heading-3', '### '],
    ['bullet-list', '- '], ['numbered-list', '1. '], ['task-list', '- [ ] '],
    ['quote', '> '], ['code', '```\n\n```'],
]) test(`slash command /${command} inserts Markdown`, async ({ page }) => {
    await write(page, '/' + command);
    await expect(page.getByRole('option')).toHaveCount(1);
    await page.keyboard.press('Enter');
    await expect(source(page)).toHaveValue(markdown);
    await expect(page.getByRole('listbox')).toHaveCount(0);
    await page.keyboard.insertText('Text');
    await expect(source(page)).toHaveValue(command === 'code' ? '```\nText\n```' : markdown + 'Text');
    expect(await page.evaluate(() => new FormData(document.querySelector('form')).get('body')))
        .toBe(await source(page).inputValue());
});

test('slash menu filters, supports arrow keys, and undoes one insertion', async ({ page }) => {
    await write(page, '/');
    await expect(page.getByRole('option')).toHaveCount(9);
    await page.keyboard.insertText('heading');
    await expect(page.getByRole('option')).toHaveCount(3);
    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('ArrowUp');
    await page.keyboard.press('Enter');
    await expect(source(page)).toHaveValue('## ');
    await page.keyboard.press('ControlOrMeta+z');
    await expect(source(page)).toHaveValue('/heading');
});

test('slash commands support clicking and Escape leaves the source intact', async ({ page }) => {
    await write(page, '/');
    await page.getByRole('option', { name: '/quote', exact: false }).click();
    await expect(source(page)).toHaveValue('> ');
    await expect(field(page)).toBeFocused();
    await write(page, '/heading-1');
    await expect(page.getByRole('listbox')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.getByRole('listbox')).toHaveCount(0);
    await expect(source(page)).toHaveValue('/heading-1');
    await page.keyboard.press('Enter');
    await expect(source(page)).toHaveValue('/heading-1\n');
});

test('ordinary slashes, unknown commands, and code or HTML stay literal', async ({ page }) => {
    for (const text of ['Text /heading-1', 'https://example.com/', '/unknown', '```\n/heading-1', '    /heading-1', '<div>\n/heading-1']) {
        await write(page, text);
        // Completion sources run asynchronously after typing.
        await page.waitForTimeout(200);
        await expect(page.getByRole('listbox')).toHaveCount(0);
        await expect(source(page)).toHaveValue(text);
    }
});

test('slash insertion respects maxlength and a field becoming readonly', async ({ page }) => {
    await source(page).evaluate(el => { el.maxLength = 5; });
    await write(page, '/code');
    await expect(page.getByRole('listbox')).toBeVisible();
    await page.keyboard.press('Enter');
    await expect(source(page)).toHaveValue('/code');
    await source(page).evaluate(el => { el.maxLength = 100; el.readOnly = true; });
    await expect(field(page)).toHaveAttribute('contenteditable', 'false');
    await page.keyboard.press('Enter');
    await expect(source(page)).toHaveValue('/code');
});

test('tables and images render until the cursor enters them', async ({ page }) => {
    const markdown = 'Intro\n\n| Plan | Price |\n| --- | --- |\n| Pro | $9 |\n\n![Logo](data:image/gif;base64,R0lGODlhAQABAAAAACw=)';
    await page.locator('oxidt-markdown-editor').evaluate((el, value) => el.editor.setValue(value, false), markdown);
    await expect(page.locator('.md-table td').first()).toHaveText('Pro');
    await expect(page.locator('img.md-image')).toHaveAttribute('alt', 'Logo');
    await page.locator('.md-table').click();
    await expect(page.locator('.md-table')).toHaveCount(0);
    await expect(field(page)).toContainText('| --- | --- |');
    await expect(page.locator('img.md-image')).toHaveCount(1);
    await page.keyboard.press('ControlOrMeta+End');
    await expect(page.locator('.md-table')).toHaveCount(1);
    await expect(page.locator('img.md-image')).toHaveCount(0);
    await expect(source(page)).toHaveValue(markdown);
});

test('diagram command inserts editable Mermaid and undoes in one step', async ({ page }) => {
    await write(page, '/diagram');
    await expect(page.getByRole('option')).toHaveCount(1);
    await page.keyboard.press('Enter');
    await expect(source(page)).toHaveValue('```mermaid\nflowchart LR\n    A --> B\n```');
    await expect(field(page)).toContainText('```mermaid');
    expect(await source(page).evaluate(el => el.selectionStart)).toBe(10);
    await page.keyboard.press('ControlOrMeta+z');
    await expect(source(page)).toHaveValue('/diagram');
});

test('diagrams render, reveal their source, update after editing, and preserve form values', async ({ page }) => {
    const markdown = 'Before\n\n```mermaid\nflowchart LR\n    A[Draft] --> B[Published]\n```\n\nAfter';
    await source(page).evaluate((el, text) => { el.value = text; }, markdown);
    await expect(page.locator('.md-diagram svg')).toBeVisible();
    await expect(page.locator('.md-diagram')).toContainText('Published');
    await page.locator('.md-diagram').click();
    await expect(page.locator('.md-diagram')).toHaveCount(0);
    await expect(field(page)).toContainText('```mermaid');
    await expect(source(page)).toHaveValue(markdown);
    await page.keyboard.press('ControlOrMeta+End');
    await expect(page.locator('.md-diagram svg')).toBeVisible();
    const updated = markdown.replace('Published', 'Done');
    await source(page).evaluate((el, text) => { el.value = text; }, updated);
    await expect(page.locator('.md-diagram')).toContainText('Done');
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    expect(await page.evaluate(() => new FormData(document.querySelector('form')).get('body'))).toBe(updated);
    expect(await page.evaluate(() => window.inputs)).toBe(0);
});

test('invalid diagrams show safe text and can be corrected', async ({ page }) => {
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    const invalid = '```mermaid\nnot a diagram <img src=x onerror=alert(1)>\n```';
    await source(page).evaluate((el, text) => { el.value = text; }, invalid);
    await expect(page.locator('.md-diagram-error')).toBeVisible();
    await expect(page.locator('.md-diagram pre')).toContainText('<img src=x onerror=alert(1)>');
    await expect(page.locator('.md-diagram img')).toHaveCount(0);
    await page.locator('.md-diagram').click();
    await expect(field(page)).toContainText('```mermaid');
    await write(page, '```mermaid\nsequenceDiagram\n    Alice->>Bob: Hello\n```');
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(page.locator('.md-diagram svg.pele-sequence')).toBeVisible();
    await expect(page.locator('.md-diagram-error')).toHaveCount(0);
    expect(errors).toEqual([]);
});

test('diagram previews fit narrow editors, inherit colors, and do not navigate', async ({ page }) => {
    await page.setViewportSize({ width: 360, height: 740 });
    await page.locator('oxidt-markdown-editor').evaluate(el => {
        el.style.setProperty('--md-editor-color', '#eeeeee');
        el.style.setProperty('--md-editor-background', '#111111');
        el.style.setProperty('--md-editor-code-background', '#333333');
    });
    await source(page).evaluate(el => {
        el.value = '```mermaid\nflowchart LR\n A[First step] --> B[Second step] --> C[Third step] --> D[Last step]\n click A "https://example.com"\n```';
    });
    const svg = page.locator('.md-diagram svg');
    await expect(svg).toBeVisible();
    await expect(svg.locator('a')).toHaveCount(0);
    await expect(svg).toHaveCSS('color', 'rgb(238, 238, 238)');
    const size = await svg.boundingBox();
    const editor = await page.locator('.cm-editor').boundingBox();
    expect(size.width).toBeLessThanOrEqual(editor.width);
    await page.locator('oxidt-markdown-editor').evaluate(el => el.style.setProperty('--md-editor-color', '#222222'));
    await expect(svg).toHaveCSS('color', 'rgb(34, 34, 34)');
});

test('a disabled fieldset disables the editor', async ({ page }) => {
    await page.evaluate(() => {
        const fieldset = document.createElement('fieldset');
        const form = document.querySelector('form');
        form.prepend(fieldset);
        fieldset.append(form.querySelector('oxidt-markdown-editor'));
        fieldset.disabled = true;
    });
    await expect(field(page)).toHaveAttribute('contenteditable', 'false');
    expect(await page.locator('oxidt-markdown-editor').evaluate(el => el.editor.insert(0, 'x'))).toBe(false);
    await page.locator('fieldset').evaluate(el => { el.disabled = false; });
    await expect(field(page)).toHaveAttribute('contenteditable', 'true');
});

test('name, requirement, errors, and placeholder follow the textarea', async ({ page }) => {
    await expect(field(page)).toHaveAttribute('aria-required', 'true');
    await source(page).evaluate(el => {
        el.removeAttribute('aria-label');
        el.setAttribute('aria-invalid', 'true');
        el.setAttribute('aria-describedby', 'body-error');
        el.placeholder = 'Say something';
    });
    await expect(field(page)).toHaveAttribute('aria-label', 'Message');
    await expect(field(page)).toHaveAttribute('aria-invalid', 'true');
    await expect(field(page)).toHaveAttribute('aria-describedby', 'body-error');
    await write(page, '');
    await expect(page.locator('.cm-placeholder')).toHaveText('Say something');
});

test('reset still applies after the field moves to another form', async ({ page }) => {
    await page.evaluate(() => {
        const other = document.createElement('form');
        document.body.append(other);
        other.append(document.querySelector('oxidt-markdown-editor'));
    });
    await write(page, '# Changed');
    await page.evaluate(() => document.querySelectorAll('form')[1].reset());
    await expect(source(page)).toHaveValue('# Original\n\n**Text**');
    await expect(page.locator('.md-h1')).toHaveText('Original');
});

// Frameworks such as Topcoat patch server HTML into the live page: they drop
// attributes and inline styles the server did not render and rewrite text.
test('an in-place re-render keeps the editor working and the textarea hidden', async ({ page }) => {
    await write(page, '# Kept');
    await page.evaluate(() => {
        const el = document.querySelector('oxidt-markdown-editor');
        el.removeAttribute('style');
        const textarea = el.querySelector('textarea');
        textarea.removeAttribute('hidden');
        el.querySelector('[data-editor-host]').replaceChildren();
    });
    await expect(source(page)).toBeHidden();
    await expect(field(page)).toBeVisible();
    await expect(page.locator('.md-h1')).toContainText('Kept');
    await page.keyboard.insertText('!');
    await expect(source(page)).toHaveValue('# Kept!');
});

test('a pristine field follows re-rendered server text; an edited one keeps the user\'s text', async ({ page }) => {
    await source(page).evaluate(el => { el.textContent = '# From server'; });
    await expect(page.locator('.md-h1')).toHaveText('From server');
    await expect(source(page)).toHaveValue('# From server');
    await write(page, '# Mine');
    await source(page).evaluate(el => { el.textContent = '# Newer from server'; });
    await expect(source(page)).toHaveValue('# Mine');
});

test('slash-command labels can be translated', async ({ page }) => {
    await page.goto('/?labels');
    await field(page).focus();
    await page.keyboard.press('ControlOrMeta+a');
    await page.keyboard.insertText('/head');
    await expect(page.getByText('Überschrift 1')).toBeVisible();
    await expect(page.getByText('Heading 2', { exact: true })).toBeVisible();
});

test('task items tick in place and quotes hide their marker', async ({ page }) => {
    const markdown = 'Intro\n\n- [ ] Label the folders\n- [x] Cover the books\n- plain\n\n> Always through.\n\nEnd';
    await page.locator('oxidt-markdown-editor').evaluate((el, value) => el.editor.setValue(value, false), markdown);
    await field(page).focus();
    await page.keyboard.press('ControlOrMeta+End');
    const boxes = page.locator('input.md-task');
    await expect(boxes).toHaveCount(2);
    await expect(boxes.nth(0)).not.toBeChecked();
    await expect(boxes.nth(1)).toBeChecked();
    // A task shows its checkbox only; a plain item keeps its bullet.
    await expect(page.locator('.md-bullet')).toHaveCount(1);
    await expect(field(page)).not.toContainText('[x]');
    await expect(page.locator('.md-task-done')).toHaveText('Cover the books');
    const quote = page.locator('.cm-line.md-quote');
    await expect(quote).toHaveText('Always through.');
    await expect(quote).toHaveCSS('border-left-width', '3px');

    await boxes.nth(0).click();
    await expect(source(page)).toHaveValue(markdown.replace('- [ ] Label', '- [x] Label'));
    await expect(page.locator('input.md-task').nth(0)).toBeChecked();
    await page.locator('input.md-task').nth(1).click();
    await expect(source(page)).toHaveValue(markdown.replace('- [ ] Label', '- [x] Label').replace('- [x] Cover', '- [ ] Cover'));
    await page.keyboard.press('ControlOrMeta+z');
    await page.keyboard.press('ControlOrMeta+z');
    await expect(source(page)).toHaveValue(markdown);
});

test.describe('host hooks', () => {
    test.beforeEach(async ({ page }) => {
        await page.goto('/?wiki');
        await expect(field(page)).toBeVisible();
    });

    test('resolved [[links]] show their title, unresolved ones stay plain text', async ({ page }) => {
        await expect(page.locator('.md-wiki-link')).toHaveText(['Plan']);
        await expect(page.locator('.md-wiki-link')).toHaveAttribute('title', /click to open/);
        await expect(field(page)).toContainText('[[gone]]');
        await expect(page.locator('.md-link')).toHaveCount(1);
        expect(await page.evaluate(() => window.asked)).toEqual([['p1', 'gone']]);
    });

    test('a click or an arrow key from its edge shows the source; leaving shows the title', async ({ page }) => {
        await page.locator('.md-wiki-link').click();
        await expect(page.locator('.md-wiki-link')).toHaveCount(0);
        await expect(field(page)).toContainText('See [[p1]] and');
        await page.keyboard.press('End');
        await expect(page.locator('.md-wiki-link')).toHaveText(['Plan']);
        await page.keyboard.press('Home');
        for (let i = 0; i < 4; i++) await page.keyboard.press('ArrowRight');
        await expect(page.locator('.md-wiki-link')).toHaveCount(1);
        await page.keyboard.press('ArrowRight');
        await expect(page.locator('.md-wiki-link')).toHaveCount(0);
    });

    test('Backspace after a shown link deletes it as one unit', async ({ page }) => {
        await write(page, 'A [[p1]]');
        await page.keyboard.press('End');
        await page.keyboard.insertText(' ');
        await page.keyboard.press('Backspace');
        await expect(page.locator('.md-wiki-link')).toHaveText(['Plan']);
        await page.keyboard.press('Backspace');
        await expect(source(page)).toHaveValue('A ');
    });

    test('[[ completes from the host by keyboard and by mouse, one undo step each', async ({ page }) => {
        await write(page, 'Read [[br');
        await expect(page.getByRole('option')).toHaveText(['BriefPage']);
        await page.keyboard.press('Enter');
        await expect(source(page)).toHaveValue('Read [[p2]]');
        await expect(page.locator('.md-wiki-link')).toHaveText(['Brief']);
        await page.keyboard.press('ControlOrMeta+z');
        await expect(source(page)).toHaveValue('Read [[br');
        await page.keyboard.insertText('X');
        await page.keyboard.press('Backspace');
        await page.keyboard.press('Backspace');
        await page.keyboard.press('Backspace');
        await page.keyboard.insertText('pl');
        await page.getByRole('option', { name: /Plan/ }).click();
        await expect(source(page)).toHaveValue('Read [[p1]]');
    });

    test('no completion inside code', async ({ page }) => {
        await write(page, '```\n[[pl');
        await page.waitForTimeout(200);
        await expect(page.getByRole('option')).toHaveCount(0);
    });

    test('Cmd/Ctrl+click opens a link while editing; a plain click edits', async ({ page }) => {
        await write(page, 'Go [[p1]] or [site](https://example.com)\n\nend');
        await page.keyboard.press('ControlOrMeta+End');
        await page.locator('.md-wiki-link').click({ modifiers: ['ControlOrMeta'] });
        await page.getByText('site').click({ modifiers: ['ControlOrMeta'] });
        expect(await page.evaluate(() => window.links)).toEqual([
            { kind: 'wiki', target: 'p1', href: '/p/p1' },
            { kind: 'link', target: null, href: 'https://example.com' },
        ]);
    });

    test('refreshLinks asks again and the title follows', async ({ page }) => {
        await expect(page.locator('.md-wiki-link')).toHaveText(['Plan']);
        await page.evaluate(() => { window.titles.p1 = 'Plan v2'; window.titles.gone = 'Back'; });
        await page.locator('oxidt-markdown-editor').evaluate(el => el.editor.refreshLinks());
        await expect(page.locator('.md-wiki-link')).toHaveText(['Plan v2', 'Back']);
    });

    test('replace swaps a range in one undo step with the cursor after it', async ({ page }) => {
        await write(page, 'Hello world');
        expect(await page.locator('oxidt-markdown-editor').evaluate(el => el.editor.replace(6, 11, 'there'))).toBe(true);
        await page.keyboard.insertText('!');
        await expect(source(page)).toHaveValue('Hello there!');
        await page.keyboard.press('ControlOrMeta+z');
        await page.keyboard.press('ControlOrMeta+z');
        await expect(source(page)).toHaveValue('Hello world');
    });
});

test('read-only: a plain click opens a link', async ({ page }) => {
    await page.goto('/?wiki&readonly');
    await page.locator('.md-wiki-link').click();
    expect(await page.evaluate(() => window.links)).toEqual([{ kind: 'wiki', target: 'p1', href: '/p/p1' }]);
    await expect(page.locator('.md-wiki-link')).not.toHaveAttribute('title');
});

test('a bracketed word is plain text, not a link', async ({ page }) => {
    await write(page, 'A [word] and [[Plan]]\n\nend');
    await page.keyboard.press('ControlOrMeta+End');
    await expect(page.locator('.md-link')).toHaveCount(0);
    await expect(field(page)).toContainText('A [word] and [[Plan]]');
});

test('without the attributes, [[ neither completes nor resolves', async ({ page }) => {
    await write(page, 'See [[pl');
    await page.waitForTimeout(200);
    await expect(page.getByRole('option')).toHaveCount(0);
    await expect(page.locator('.md-wiki-link')).toHaveCount(0);
});

test.describe('applyRemote', () => {
    const remote = (page, ...args) => page.locator('oxidt-markdown-editor').evaluate((el, args) => el.editor.applyRemote(...args), args);
    // CodeMirror scrolls in its next measure, after a frame.
    const scrollY = page => page.evaluate(() => new Promise(done => requestAnimationFrame(() => requestAnimationFrame(() => done(window.scrollY)))));

    test('applies someone else\'s edit with no undo step, no input event, and the caret kept', async ({ page }) => {
        await write(page, 'Mine\n\nTheirs');
        await page.keyboard.press('ControlOrMeta+Home');
        await page.keyboard.press('End');
        const inputs = await page.evaluate(() => window.inputs);
        expect(await remote(page, 6, 12, 'Their edit')).toBe(true);
        await expect(source(page)).toHaveValue('Mine\n\nTheir edit');
        expect(await page.evaluate(() => window.inputs)).toBe(inputs);
        expect(await source(page).evaluate(el => [el.selectionStart, el.selectionEnd])).toEqual([4, 4]);
        await expect(field(page)).toBeFocused();
        await page.keyboard.insertText('!');
        await expect(source(page)).toHaveValue('Mine!\n\nTheir edit');
        await page.keyboard.press('ControlOrMeta+z');
        await expect(source(page)).toHaveValue('Mine\n\nTheir edit');
        // Redo is Mod-y off the Mac; Ctrl+Shift+Z is not bound on every platform.
        await page.keyboard.press(process.platform === 'darwin' ? 'Meta+Shift+z' : 'Control+y');
        await expect(source(page)).toHaveValue('Mine!\n\nTheir edit');
    });

    test('a list of changes applies at once; an invalid one changes nothing', async ({ page }) => {
        expect(await remote(page, [{ from: 12, to: 20, text: 'Body' }, { from: 0, to: 10, text: '# Title' }])).toBe(true);
        await expect(source(page)).toHaveValue('# Title\n\nBody');
        expect(await remote(page, 2, 99, 'x')).toBe(false);
        await expect(source(page)).toHaveValue('# Title\n\nBody');
    });

    test('works without focus and does not take it', async ({ page }) => {
        const reset = page.getByRole('button', { name: 'Reset', exact: true });
        await reset.focus();
        expect(await remote(page, 0, 10, '# Theirs')).toBe(true);
        await expect(source(page)).toHaveValue('# Theirs\n\n**Text**');
        await expect(reset).toBeFocused();
        await expect(page.locator('.md-h1')).toHaveText('Theirs');
        expect(await page.evaluate(() => window.inputs)).toBe(0);
        await field(page).focus();
        await page.keyboard.press('ControlOrMeta+z');
        await expect(source(page)).toHaveValue('# Theirs\n\n**Text**');
    });

    test('scrolls only to keep a caret that was in view', async ({ page }) => {
        const lines = Array.from({ length: 80 }, (_, i) => 'Line ' + i).join('\n');
        await write(page, lines);
        await page.keyboard.press('ControlOrMeta+Home');
        await page.evaluate(() => window.scrollTo(0, 0));
        // A change below the caret: nothing moves.
        expect(await remote(page, lines.length, lines.length, '\nmore')).toBe(true);
        expect(await scrollY(page)).toBe(0);
        // Lines above the caret push it off screen: the view follows it.
        await page.keyboard.press('ArrowDown');
        expect(await remote(page, 0, 0, 'New\n'.repeat(60))).toBe(true);
        await expect(field(page).getByText('Line 1', { exact: true })).toBeInViewport();
        expect(await scrollY(page)).toBeGreaterThan(0);
        // Without focus nothing scrolls.
        await page.keyboard.press('ControlOrMeta+Home');
        await page.keyboard.press('ArrowDown');
        await scrollY(page);
        await page.evaluate(() => { document.activeElement.blur(); window.scrollTo(0, 0); });
        expect(await scrollY(page)).toBe(0);
        expect(await remote(page, 0, 0, 'Old\n'.repeat(60))).toBe(true);
        expect(await scrollY(page)).toBe(0);
    });

    test('waits for an IME composition to end', async ({ page }) => {
        await write(page, 'Hi ');
        const cdp = await page.context().newCDPSession(page);
        await cdp.send('Input.imeSetComposition', { text: 'に', selectionStart: 1, selectionEnd: 1 });
        expect(await remote(page, 0, 0, 'X')).toBe(false);
        await cdp.send('Input.insertText', { text: 'に' });
        await expect(source(page)).toHaveValue('Hi に');
        expect(await remote(page, 0, 0, 'X')).toBe(true);
        await expect(source(page)).toHaveValue('XHi に');
    });
});

test('applyRemote keeps [[links]] shown and resolves new ones', async ({ page }) => {
    await page.goto('/?wiki');
    await expect(page.locator('.md-wiki-link')).toHaveText(['Plan']);
    expect(await page.locator('oxidt-markdown-editor').evaluate(el => el.editor.applyRemote(0, 0, 'Also [[p2]]. '))).toBe(true);
    await expect(source(page)).toHaveValue('Also [[p2]]. See [[p1]] and [[gone]].');
    await expect(page.locator('.md-wiki-link')).toHaveText(['Brief', 'Plan']);
});
