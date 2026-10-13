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
    await page.locator('oxidt-markdown-editor').evaluate(el => el.setAttribute('data-value', '# Restored'));
    await expect(source(page)).toHaveValue('# Restored');
    await expect(page.locator('.md-h1')).toHaveText('Restored');
    expect(await page.evaluate(() => window.inputs)).toBe(0);
    await field(page).focus();
    await expect(page.locator('.md-h1')).toHaveText('# Restored');
});

test('image insertion is an independent undo step', async ({ page }) => {
    await write(page, 'Before');
    await page.locator('oxidt-markdown-editor').evaluate(el => el.editor.insert(6, '\n\n![image](image.png)'));
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
    await expect(page.getByRole('option')).toHaveCount(8);
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
    await page.locator('oxidt-markdown-editor').evaluate((el, value) => el.setAttribute('data-value', value), markdown);
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
