const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../db/connection');

const router = express.Router();

function getDbErrorMessage(error) {
    if (error && error.code === 'ER_ACCESS_DENIED_ERROR') {
        return 'Não foi possível conectar à base de dados. Verifica as credenciais do MySQL em .env (DB_HOST, DB_USER, DB_PASSWORD e DB_NAME).';
    }

    if (error && error.code === 'ER_BAD_DB_ERROR') {
        return 'A base de dados indicada não existe. Confirma o valor de DB_NAME no ficheiro .env.';
    }

    return 'Erro ao comunicar com a base de dados.';
}

function requireAuth(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    next();
}

function formatCurrency(value) {
    return Number(value || 0).toLocaleString('pt-PT', {
        style: 'currency',
        currency: 'EUR'
    });
}

function getCurrentMonthAndYear() {
    const now = new Date();
    return {
        month: now.getMonth() + 1,
        year: now.getFullYear()
    };
}

router.get('/', (req, res) => {
    if (req.session.user) {
        return res.redirect('/dashboard');
    }

    res.render('home', {
        title: 'FinTrack | Gestão das tuas finanças',
        user: null
    });
});

router.get('/login', (req, res) => {
    if (req.session.user) {
        return res.redirect('/dashboard');
    }

    res.render('login', {
        title: 'Entrar',
        error: null,
        formData: {}
    });
});

router.post('/login', async (req, res) => {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    if (!email || !password) {
        return res.status(400).render('login', {
            title: 'Entrar',
            error: 'Preenche o email e a palavra-passe.',
            formData: { email }
        });
    }

    try {
        const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);

        if (rows.length === 0) {
            return res.status(401).render('login', {
                title: 'Entrar',
                error: 'Credenciais inválidas.',
                formData: { email }
            });
        }

        const user = rows[0];
        const isValidPassword = await bcrypt.compare(password, user.password_hash);

        if (!isValidPassword) {
            return res.status(401).render('login', {
                title: 'Entrar',
                error: 'Credenciais inválidas.',
                formData: { email }
            });
        }

        req.session.user = {
            id: user.id,
            name: user.name,
            email: user.email
        };

        req.session.save(() => {
            res.redirect('/dashboard');
        });
    } catch (error) {
        console.error('Erro no login:', error);
        res.status(500).render('login', {
            title: 'Entrar',
            error: getDbErrorMessage(error),
            formData: { email }
        });
    }
});

router.get('/register', (req, res) => {
    if (req.session.user) {
        return res.redirect('/dashboard');
    }

    res.render('register', {
        title: 'Criar conta',
        error: null,
        formData: {}
    });
});

router.post('/register', async (req, res) => {
    const name = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const confirmPassword = String(req.body.confirmPassword || '');

    if (!name || !email || !password || !confirmPassword) {
        return res.status(400).render('register', {
            title: 'Criar conta',
            error: 'Preenche todos os campos.',
            formData: { name, email }
        });
    }

    if (name.length < 2) {
        return res.status(400).render('register', {
            title: 'Criar conta',
            error: 'O nome tem de ter pelo menos 2 caracteres.',
            formData: { name, email }
        });
    }

    if (password.length < 8) {
        return res.status(400).render('register', {
            title: 'Criar conta',
            error: 'A palavra-passe deve ter pelo menos 8 caracteres.',
            formData: { name, email }
        });
    }

    if (password !== confirmPassword) {
        return res.status(400).render('register', {
            title: 'Criar conta',
            error: 'As palavras-passe não coincidem.',
            formData: { name, email }
        });
    }

    try {
        const [existingUsers] = await db.execute('SELECT id FROM users WHERE email = ?', [email]);

        if (existingUsers.length > 0) {
            return res.status(409).render('register', {
                title: 'Criar conta',
                error: 'Já existe uma conta com este email.',
                formData: { name, email }
            });
        }

        const passwordHash = await bcrypt.hash(password, 12);
        const [result] = await db.execute(
            'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
            [name, email, passwordHash]
        );

        req.session.user = {
            id: result.insertId,
            name,
            email
        };

        req.session.save(() => {
            res.redirect('/dashboard');
        });
    } catch (error) {
        console.error('Erro no registo:', error);
        res.status(500).render('register', {
            title: 'Criar conta',
            error: getDbErrorMessage(error),
            formData: { name, email }
        });
    }
});

router.post('/logout', requireAuth, (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Erro ao terminar sessão:', err);
        }
        res.redirect('/login');
    });
});

router.get('/dashboard', requireAuth, async (req, res) => {
    const userId = req.session.user.id;
    const { month, year } = getCurrentMonthAndYear();

    try {
        const [accounts] = await db.execute(
            'SELECT * FROM accounts WHERE user_id = ? ORDER BY created_at DESC LIMIT 5',
            [userId]
        );

        const [summary] = await db.execute(
            `SELECT
                COALESCE(SUM(CASE WHEN type = 'receita' THEN amount ELSE 0 END), 0) AS total_income,
                COALESCE(SUM(CASE WHEN type = 'despesa' THEN amount ELSE 0 END), 0) AS total_expenses,
                COALESCE(SUM(CASE WHEN type = 'receita' THEN amount ELSE 0 END), 0) - COALESCE(SUM(CASE WHEN type = 'despesa' THEN amount ELSE 0 END), 0) AS balance
             FROM transactions
             WHERE user_id = ?`,
            [userId]
        );

        const [monthlySummary] = await db.execute(
            `SELECT
                COALESCE(SUM(CASE WHEN type = 'receita' THEN amount ELSE 0 END), 0) AS month_income,
                COALESCE(SUM(CASE WHEN type = 'despesa' THEN amount ELSE 0 END), 0) AS month_expenses,
                COALESCE(SUM(CASE WHEN type = 'receita' THEN amount ELSE 0 END), 0) - COALESCE(SUM(CASE WHEN type = 'despesa' THEN amount ELSE 0 END), 0) AS month_balance
             FROM transactions
             WHERE user_id = ?
               AND MONTH(transaction_date) = ?
               AND YEAR(transaction_date) = ?`,
            [userId, month, year]
        );

        const [recentTransactions] = await db.execute(
            `SELECT t.*, a.name AS account_name, c.name AS category_name
             FROM transactions t
             LEFT JOIN accounts a ON a.id = t.account_id
             LEFT JOIN categories c ON c.id = t.category_id
             WHERE t.user_id = ?
             ORDER BY t.transaction_date DESC, t.created_at DESC
             LIMIT 6`,
            [userId]
        );

        const [accountBalance] = await db.execute(
            'SELECT COALESCE(SUM(current_balance), 0) AS total_balance FROM accounts WHERE user_id = ?',
            [userId]
        );

        const [budgetRows] = await db.execute(
            `SELECT b.*, c.name AS category_name, c.color, c.type AS category_type
             FROM budgets b
             INNER JOIN categories c ON c.id = b.category_id
             WHERE b.user_id = ? AND b.period_month = ? AND b.period_year = ?
             ORDER BY c.name ASC`,
            [userId, month, year]
        );

        const budgetStatus = await Promise.all(
            budgetRows.map(async (budget) => {
                const [spentRows] = await db.execute(
                    `SELECT COALESCE(SUM(amount), 0) AS spent
                     FROM transactions
                     WHERE user_id = ?
                       AND category_id = ?
                       AND type = 'despesa'
                       AND MONTH(transaction_date) = ?
                       AND YEAR(transaction_date) = ?`,
                    [userId, budget.category_id, month, year]
                );

                const spent = Number(spentRows[0]?.spent || 0);
                const amountLimit = Number(budget.amount_limit || 0);
                const remaining = amountLimit - spent;
                const percent = amountLimit > 0 ? Math.min((spent / amountLimit) * 100, 100) : 0;

                return {
                    ...budget,
                    spent,
                    remaining,
                    percent,
                    alert: spent > amountLimit
                };
            })
        );

        const [categorySpendRows] = await db.execute(
            `SELECT c.name, c.color, COALESCE(SUM(t.amount), 0) AS total
             FROM transactions t
             LEFT JOIN categories c ON c.id = t.category_id
             WHERE t.user_id = ?
               AND t.type = 'despesa'
               AND MONTH(t.transaction_date) = ?
               AND YEAR(t.transaction_date) = ?
             GROUP BY c.id, c.name, c.color
             ORDER BY total DESC
             LIMIT 5`,
            [userId, month, year]
        );

        res.render('dashboard', {
            title: 'Dashboard',
            user: req.session.user,
            accounts,
            summary: summary[0],
            monthlySummary: monthlySummary[0],
            recentTransactions,
            totalBalance: Number(accountBalance[0].total_balance || 0),
            budgetStatus,
            categorySpendRows,
            month,
            year,
            formatCurrency
        });
    } catch (error) {
        console.error('Erro ao carregar dashboard:', error);
        res.status(500).render('error', {
            title: 'Erro no dashboard',
            message: 'Não foi possível carregar a sua dashboard.',
            user: req.session.user
        });
    }
});

router.get('/accounts', requireAuth, async (req, res) => {
    try {
        const userId = req.session.user.id;
        const [accounts] = await db.execute(
            'SELECT * FROM accounts WHERE user_id = ? ORDER BY created_at DESC',
            [userId]
        );

        res.render('accounts', {
            title: 'Contas',
            user: req.session.user,
            accounts,
            formatCurrency
        });
    } catch (error) {
        console.error('Erro ao listar contas:', error);
        res.status(500).render('error', {
            title: 'Erro nas contas',
            message: 'Não foi possível carregar as contas.',
            user: req.session.user
        });
    }
});

router.get('/accounts/new', requireAuth, (req, res) => {
    res.render('account-form', {
        title: 'Nova conta',
        user: req.session.user,
        account: null,
        error: null
    });
});

router.post('/accounts/new', requireAuth, async (req, res) => {
    const userId = req.session.user.id;
    const name = String(req.body.name || '').trim();
    const type = String(req.body.type || 'corrente');
    const initialBalance = Number(req.body.initial_balance || 0);
    const currency = String(req.body.currency || 'EUR').toUpperCase();

    if (!name) {
        return res.status(400).render('account-form', {
            title: 'Nova conta',
            user: req.session.user,
            account: { name, type, initial_balance: initialBalance, currency },
            error: 'O nome da conta é obrigatório.'
        });
    }

    try {
        await db.execute(
            'INSERT INTO accounts (user_id, name, type, initial_balance, current_balance, currency) VALUES (?, ?, ?, ?, ?, ?)',
            [userId, name, type, initialBalance, initialBalance, currency]
        );

        res.redirect('/accounts');
    } catch (error) {
        console.error('Erro ao criar conta:', error);
        res.status(500).render('account-form', {
            title: 'Nova conta',
            user: req.session.user,
            account: { name, type, initial_balance: initialBalance, currency },
            error: getDbErrorMessage(error)
        });
    }
});

router.get('/accounts/:id/edit', requireAuth, async (req, res) => {
    try {
        const [rows] = await db.execute('SELECT * FROM accounts WHERE id = ? AND user_id = ?', [req.params.id, req.session.user.id]);

        if (rows.length === 0) {
            return res.status(404).render('error', {
                title: 'Conta não encontrada',
                message: 'A conta pedida não existe ou não pertence a este utilizador.',
                user: req.session.user
            });
        }

        res.render('account-form', {
            title: 'Editar conta',
            user: req.session.user,
            account: rows[0],
            error: null
        });
    } catch (error) {
        console.error('Erro ao carregar conta:', error);
        res.status(500).render('error', {
            title: 'Erro ao editar conta',
            message: 'Não foi possível carregar a conta.',
            user: req.session.user
        });
    }
});

router.post('/accounts/:id/edit', requireAuth, async (req, res) => {
    const userId = req.session.user.id;
    const id = req.params.id;
    const name = String(req.body.name || '').trim();
    const type = String(req.body.type || 'corrente');
    const currency = String(req.body.currency || 'EUR').toUpperCase();

    if (!name) {
        return res.status(400).render('account-form', {
            title: 'Editar conta',
            user: req.session.user,
            account: { id, name, type, currency },
            error: 'O nome da conta é obrigatório.'
        });
    }

    try {
        await db.execute(
            'UPDATE accounts SET name = ?, type = ?, currency = ? WHERE id = ? AND user_id = ?',
            [name, type, currency, id, userId]
        );

        res.redirect('/accounts');
    } catch (error) {
        console.error('Erro ao guardar conta:', error);
        res.status(500).render('account-form', {
            title: 'Editar conta',
            user: req.session.user,
            account: { id, name, type, currency },
            error: getDbErrorMessage(error)
        });
    }
});

router.post('/accounts/:id/delete', requireAuth, async (req, res) => {
    try {
        await db.execute('DELETE FROM accounts WHERE id = ? AND user_id = ?', [req.params.id, req.session.user.id]);
        res.redirect('/accounts');
    } catch (error) {
        console.error('Erro ao eliminar conta:', error);
        res.status(500).render('error', {
            title: 'Erro ao eliminar conta',
            message: 'Não foi possível remover a conta.',
            user: req.session.user
        });
    }
});

router.get('/categories', requireAuth, async (req, res) => {
    try {
        const userId = req.session.user.id;
        const [categories] = await db.execute(
            'SELECT * FROM categories WHERE user_id IS NULL OR user_id = ? ORDER BY user_id IS NULL, name ASC',
            [userId]
        );

        const [statsRows] = await db.execute(
            `SELECT
                COUNT(*) AS total_categories,
                SUM(CASE WHEN user_id IS NULL THEN 1 ELSE 0 END) AS default_categories,
                SUM(CASE WHEN user_id = ? THEN 1 ELSE 0 END) AS personal_categories,
                SUM(CASE WHEN type = 'receita' THEN 1 ELSE 0 END) AS receitas,
                SUM(CASE WHEN type = 'despesa' THEN 1 ELSE 0 END) AS despesas
             FROM categories
             WHERE user_id IS NULL OR user_id = ?`,
            [userId, userId]
        );

        const stats = statsRows[0] || {
            total_categories: 0,
            default_categories: 0,
            personal_categories: 0,
            receitas: 0,
            despesas: 0
        };

        res.render('categories', {
            title: 'Categorias',
            user: req.session.user,
            categories,
            stats,
            formatCurrency
        });
    } catch (error) {
        console.error('Erro ao listar categorias:', error);
        res.status(500).render('error', {
            title: 'Erro nas categorias',
            message: 'Não foi possível carregar as categorias.',
            user: req.session.user
        });
    }
});

router.get('/categories/new', requireAuth, (req, res) => {
    res.render('category-form', {
        title: 'Nova categoria',
        user: req.session.user,
        category: null,
        error: null
    });
});

router.post('/categories/new', requireAuth, async (req, res) => {
    const userId = req.session.user.id;
    const name = String(req.body.name || '').trim();
    const type = String(req.body.type || 'despesa');
    const icon = String(req.body.icon || '').trim();
    const color = String(req.body.color || '#22c55e').trim();

    if (!name) {
        return res.status(400).render('category-form', {
            title: 'Nova categoria',
            user: req.session.user,
            category: { name, type, icon, color },
            error: 'O nome da categoria é obrigatório.'
        });
    }

    try {
        await db.execute(
            'INSERT INTO categories (user_id, name, type, icon, color) VALUES (?, ?, ?, ?, ?)',
            [userId, name, type, icon || null, color]
        );

        res.redirect('/categories');
    } catch (error) {
        console.error('Erro ao criar categoria:', error);
        res.status(500).render('category-form', {
            title: 'Nova categoria',
            user: req.session.user,
            category: { name, type, icon, color },
            error: getDbErrorMessage(error)
        });
    }
});

router.get('/categories/:id/edit', requireAuth, async (req, res) => {
    try {
        const [rows] = await db.execute(
            'SELECT * FROM categories WHERE id = ? AND user_id = ?',
            [req.params.id, req.session.user.id]
        );

        if (rows.length === 0) {
            return res.status(404).render('error', {
                title: 'Categoria não encontrada',
                message: 'A categoria pedida não existe ou não pertence ao utilizador atual.',
                user: req.session.user
            });
        }

        res.render('category-form', {
            title: 'Editar categoria',
            user: req.session.user,
            category: rows[0],
            error: null
        });
    } catch (error) {
        console.error('Erro ao carregar categoria:', error);
        res.status(500).render('error', {
            title: 'Erro ao editar categoria',
            message: 'Não foi possível carregar a categoria.',
            user: req.session.user
        });
    }
});

router.post('/categories/:id/edit', requireAuth, async (req, res) => {
    const userId = req.session.user.id;
    const id = req.params.id;
    const name = String(req.body.name || '').trim();
    const type = String(req.body.type || 'despesa');
    const icon = String(req.body.icon || '').trim();
    const color = String(req.body.color || '#22c55e').trim();

    if (!name) {
        return res.status(400).render('category-form', {
            title: 'Editar categoria',
            user: req.session.user,
            category: { id, name, type, icon, color },
            error: 'O nome da categoria é obrigatório.'
        });
    }

    try {
        await db.execute(
            'UPDATE categories SET name = ?, type = ?, icon = ?, color = ? WHERE id = ? AND user_id = ?',
            [name, type, icon || null, color, id, userId]
        );

        res.redirect('/categories');
    } catch (error) {
        console.error('Erro ao atualizar categoria:', error);
        res.status(500).render('category-form', {
            title: 'Editar categoria',
            user: req.session.user,
            category: { id, name, type, icon, color },
            error: getDbErrorMessage(error)
        });
    }
});

router.post('/categories/:id/delete', requireAuth, async (req, res) => {
    try {
        await db.execute('DELETE FROM categories WHERE id = ? AND user_id = ?', [req.params.id, req.session.user.id]);
        res.redirect('/categories');
    } catch (error) {
        console.error('Erro ao eliminar categoria:', error);
        res.status(500).render('error', {
            title: 'Erro ao eliminar categoria',
            message: 'Não foi possível remover a categoria.',
            user: req.session.user
        });
    }
});

router.get('/budgets', requireAuth, async (req, res) => {
    const userId = req.session.user.id;
    const { month, year } = getCurrentMonthAndYear();

    try {
        const [budgets] = await db.execute(
            `SELECT b.*, c.name AS category_name, c.type AS category_type, c.color
             FROM budgets b
             INNER JOIN categories c ON c.id = b.category_id
             WHERE b.user_id = ? AND b.period_month = ? AND b.period_year = ?
             ORDER BY c.name ASC`,
            [userId, month, year]
        );

        const [categories] = await db.execute(
            'SELECT * FROM categories WHERE user_id IS NULL OR user_id = ? ORDER BY name ASC',
            [userId]
        );

        const budgetProgress = await Promise.all(
            budgets.map(async (budget) => {
                const [spentRows] = await db.execute(
                    `SELECT COALESCE(SUM(amount), 0) AS spent
                     FROM transactions
                     WHERE user_id = ?
                       AND category_id = ?
                       AND type = 'despesa'
                       AND MONTH(transaction_date) = ?
                       AND YEAR(transaction_date) = ?`,
                    [userId, budget.category_id, month, year]
                );

                const spent = Number(spentRows[0]?.spent || 0);

                return {
                    ...budget,
                    spent,
                    remaining: Number(budget.amount_limit) - spent
                };
            })
        );

        res.render('budgets', {
            title: 'Orçamentos',
            user: req.session.user,
            budgets: budgetProgress,
            categories,
            month,
            year,
            formatCurrency
        });
    } catch (error) {
        console.error('Erro ao listar orçamentos:', error);
        res.status(500).render('error', {
            title: 'Erro nos orçamentos',
            message: 'Não foi possível carregar os orçamentos.',
            user: req.session.user
        });
    }
});

router.get('/budgets/new', requireAuth, async (req, res) => {
    const userId = req.session.user.id;
    const { month, year } = getCurrentMonthAndYear();

    try {
        const [categories] = await db.execute(
            'SELECT * FROM categories WHERE user_id IS NULL OR user_id = ? ORDER BY name ASC',
            [userId]
        );

        res.render('budget-form', {
            title: 'Novo orçamento',
            user: req.session.user,
            categories,
            budget: { period_month: month, period_year: year },
            error: null
        });
    } catch (error) {
        console.error('Erro ao preparar orçamento:', error);
        res.status(500).render('error', {
            title: 'Erro ao preparar orçamento',
            message: 'Não foi possível carregar o formulário de orçamento.',
            user: req.session.user
        });
    }
});

router.post('/budgets/new', requireAuth, async (req, res) => {
    const userId = req.session.user.id;
    const categoryId = Number(req.body.category_id);
    const amountLimit = Number(req.body.amount_limit || 0);
    const periodMonth = Number(req.body.period_month || getCurrentMonthAndYear().month);
    const periodYear = Number(req.body.period_year || getCurrentMonthAndYear().year);

    try {
        const [categories] = await db.execute(
            'SELECT * FROM categories WHERE user_id IS NULL OR user_id = ? ORDER BY name ASC',
            [userId]
        );

        if (!categoryId || !amountLimit || amountLimit <= 0) {
            return res.status(400).render('budget-form', {
                title: 'Novo orçamento',
                user: req.session.user,
                categories,
                budget: { category_id: categoryId, amount_limit: amountLimit, period_month: periodMonth, period_year: periodYear },
                error: 'Define uma categoria e um valor válido para o orçamento.'
            });
        }

        await db.execute(
            'INSERT INTO budgets (user_id, category_id, amount_limit, period_month, period_year) VALUES (?, ?, ?, ?, ?)',
            [userId, categoryId, amountLimit, periodMonth, periodYear]
        );

        res.redirect('/budgets');
    } catch (error) {
        console.error('Erro ao criar orçamento:', error);
        res.status(500).render('error', {
            title: 'Erro ao criar orçamento',
            message: getDbErrorMessage(error),
            user: req.session.user
        });
    }
});

router.post('/budgets/:id/delete', requireAuth, async (req, res) => {
    try {
        await db.execute('DELETE FROM budgets WHERE id = ? AND user_id = ?', [req.params.id, req.session.user.id]);
        res.redirect('/budgets');
    } catch (error) {
        console.error('Erro ao remover orçamento:', error);
        res.status(500).render('error', {
            title: 'Erro ao remover orçamento',
            message: 'Não foi possível remover o orçamento.',
            user: req.session.user
        });
    }
});

router.get('/transactions', requireAuth, async (req, res) => {
    const userId = req.session.user.id;

    try {
        const [transactions] = await db.execute(
            `SELECT t.*, a.name AS account_name, c.name AS category_name, d.name AS destination_name
             FROM transactions t
             LEFT JOIN accounts a ON a.id = t.account_id
             LEFT JOIN accounts d ON d.id = t.destination_account_id
             LEFT JOIN categories c ON c.id = t.category_id
             WHERE t.user_id = ?
             ORDER BY t.transaction_date DESC, t.created_at DESC`,
            [userId]
        );

        res.render('transactions', {
            title: 'Transações',
            user: req.session.user,
            transactions,
            formatCurrency
        });
    } catch (error) {
        console.error('Erro ao listar transações:', error);
        res.status(500).render('error', {
            title: 'Erro nas transações',
            message: 'Não foi possível carregar as transações.',
            user: req.session.user
        });
    }
});

router.get('/transactions/new', requireAuth, async (req, res) => {
    try {
        const userId = req.session.user.id;
        const [accounts] = await db.execute('SELECT * FROM accounts WHERE user_id = ? ORDER BY name ASC', [userId]);
        const [categories] = await db.execute(
            'SELECT * FROM categories WHERE user_id IS NULL OR user_id = ? ORDER BY name ASC',
            [userId]
        );

        res.render('transaction-form', {
            title: 'Nova transação',
            user: req.session.user,
            accounts,
            categories,
            transaction: null,
            error: null
        });
    } catch (error) {
        console.error('Erro ao preparar formulário de transação:', error);
        res.status(500).render('error', {
            title: 'Erro ao criar transação',
            message: 'Não foi possível carregar o formulário de transação.',
            user: req.session.user
        });
    }
});

router.post('/transactions/new', requireAuth, async (req, res) => {
    const userId = req.session.user.id;
    const accountId = Number(req.body.account_id);
    const categoryId = req.body.category_id ? Number(req.body.category_id) : null;
    const type = String(req.body.type || 'despesa');
    const amount = Number(req.body.amount || 0);
    const description = String(req.body.description || '').trim();
    const transactionDate = String(req.body.transaction_date || new Date().toISOString().slice(0, 10));
    const destinationAccountId = req.body.destination_account_id ? Number(req.body.destination_account_id) : null;

    try {
        const [accounts] = await db.execute('SELECT * FROM accounts WHERE user_id = ? ORDER BY name ASC', [userId]);
        const [categories] = await db.execute(
            'SELECT * FROM categories WHERE user_id IS NULL OR user_id = ? ORDER BY name ASC',
            [userId]
        );

        if (!accountId || !amount || amount <= 0) {
            return res.status(400).render('transaction-form', {
                title: 'Nova transação',
                user: req.session.user,
                accounts,
                categories,
                transaction: { account_id: accountId, category_id: categoryId, type, amount, description, transaction_date: transactionDate, destination_account_id: destinationAccountId },
                error: 'Introduz um montante válido.'
            });
        }

        if (type === 'transferencia' && (!destinationAccountId || destinationAccountId === accountId)) {
            return res.status(400).render('transaction-form', {
                title: 'Nova transação',
                user: req.session.user,
                accounts,
                categories,
                transaction: { account_id: accountId, category_id: categoryId, type, amount, description, transaction_date: transactionDate, destination_account_id: destinationAccountId },
                error: 'Uma transferência precisa de uma conta de destino válida.'
            });
        }

        const [accountRows] = await db.execute('SELECT * FROM accounts WHERE id = ? AND user_id = ?', [accountId, userId]);
        if (accountRows.length === 0) {
            return res.status(400).render('transaction-form', {
                title: 'Nova transação',
                user: req.session.user,
                accounts,
                categories,
                transaction: { account_id: accountId, category_id: categoryId, type, amount, description, transaction_date: transactionDate, destination_account_id: destinationAccountId },
                error: 'Conta não encontrada.'
            });
        }

        const [result] = await db.execute(
            `INSERT INTO transactions (user_id, account_id, category_id, type, amount, description, transaction_date, destination_account_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [userId, accountId, categoryId, type, amount, description || null, transactionDate, destinationAccountId]
        );

        if (type === 'receita') {
            await db.execute('UPDATE accounts SET current_balance = current_balance + ? WHERE id = ?', [amount, accountId]);
        }

        if (type === 'despesa') {
            await db.execute('UPDATE accounts SET current_balance = current_balance - ? WHERE id = ?', [amount, accountId]);
        }

        if (type === 'transferencia' && destinationAccountId) {
            await db.execute('UPDATE accounts SET current_balance = current_balance - ? WHERE id = ?', [amount, accountId]);
            await db.execute('UPDATE accounts SET current_balance = current_balance + ? WHERE id = ?', [amount, destinationAccountId]);
        }

        res.redirect('/transactions');
    } catch (error) {
        console.error('Erro ao criar transação:', error);
        res.status(500).render('error', {
            title: 'Erro ao criar transação',
            message: getDbErrorMessage(error),
            user: req.session.user
        });
    }
});

router.get('/test-db', async (req, res) => {
    try {
        const [rows] = await db.query('SELECT NOW() AS time');
        res.json(rows[0]);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;