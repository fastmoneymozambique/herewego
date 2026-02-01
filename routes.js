// routes.js
// Este arquivo define todas as rotas da API e as associa aos controladores correspondentes,
// aplicando middlewares de autenticação e autorização quando necessário.

const express = require('express');
const {
    registerUser,
    loginUser,
    getUserProfile,
    createInvestmentPlan,
    getInvestmentPlans,
    getInvestmentPlanById,
    updateInvestmentPlan,
    deleteInvestmentPlan,
    activateInvestment,
    getUserActiveInvestments,
    getUserInvestmentHistory,
    requestDeposit,
    getUserDeposits,
    getPendingDeposits,
    approveDeposit,
    rejectDeposit,
    requestWithdrawal,
    getUserWithdrawals,
    getPendingWithdrawals,
    approveWithdrawal,
    rejectWithdrawal,
    getAdminConfig,
    updateAdminConfig,
    getAllUsers,
    getUserDetails,
    blockUser,
    unblockUser,
    createAdmin,
    changeUserPasswordByAdmin,
    getBlockedUsers,
    processDailyProfitsAndCommissions,
} = require('./controllers'); // Importa todos os controladores
const { protect, authorizeAdmin } = require('./middleware'); // Importa os middlewares de segurança

const router = express.Router(); // Cria uma instância de router do Express

/**
 * @function appRoutes
 * @description Configura todas as rotas da aplicação no objeto Express 'app'.
 * @param {object} app - A instância do aplicativo Express.
 */
const appRoutes = (app) => {
    // --- Rotas de Autenticação e Usuário (Públicas e Privadas) ---
    router.post('/register', registerUser);
    router.post('/login', loginUser);
    router.get('/profile', protect, getUserProfile); // Perfil do usuário logado

    // --- Rotas de Planos de Investimento (Públicas para leitura, Admin para CRUD) ---
    router.get('/investmentplans', getInvestmentPlans); // Todos podem ver os planos
    router.get('/investmentplans/:id', getInvestmentPlanById); // Todos podem ver um plano específico

    // --- Rotas de Investimento do Usuário ---
    router.post('/investments', protect, activateInvestment); // Ativar um novo investimento
    router.get('/investments/active', protect, getUserActiveInvestments); // Ver investimentos ativos
    router.get('/investments/history', protect, getUserInvestmentHistory); // Ver histórico de investimentos

    // --- Rotas de Depósito do Usuário ---
    router.post('/deposits', protect, requestDeposit); // Solicitar um depósito
    router.get('/deposits/history', protect, getUserDeposits); // Ver histórico de depósitos do usuário

    // --- Rotas de Saque do Usuário ---
    router.post('/withdrawals', protect, requestWithdrawal); // Solicitar um saque
    router.get('/withdrawals/history', protect, getUserWithdrawals); // Ver histórico de saques do usuário

    // --- Rotas do Painel Administrativo (Exigem autenticação e autorização de Admin) ---

    // Gerenciamento de Planos de Investimento
    router.post('/admin/investmentplans', protect, authorizeAdmin, createInvestmentPlan);
    router.put('/admin/investmentplans/:id', protect, authorizeAdmin, updateInvestmentPlan);
    router.delete('/admin/investmentplans/:id', protect, authorizeAdmin, deleteInvestmentPlan);

    // Gerenciamento de Depósitos
    router.get('/admin/deposits/pending', protect, authorizeAdmin, getPendingDeposits);
    router.put('/admin/deposits/:id/approve', protect, authorizeAdmin, approveDeposit);
    router.put('/admin/deposits/:id/reject', protect, authorizeAdmin, rejectDeposit);

    // Gerenciamento de Saques
    router.get('/admin/withdrawals/pending', protect, authorizeAdmin, getPendingWithdrawals);
    router.put('/admin/withdrawals/:id/approve', protect, authorizeAdmin, approveWithdrawal);
    router.put('/admin/withdrawals/:id/reject', protect, authorizeAdmin, rejectWithdrawal);

    // Gerenciamento de Usuários
    router.get('/admin/users', protect, authorizeAdmin, getAllUsers);
    router.get('/admin/users/:id', protect, authorizeAdmin, getUserDetails);
    router.put('/admin/users/:id/block', protect, authorizeAdmin, blockUser);
    router.put('/admin/users/:id/unblock', protect, authorizeAdmin, unblockUser);
    router.post('/admin/users/create-admin', protect, authorizeAdmin, createAdmin); // Criar novos admins
    router.put('/admin/users/:id/change-password', protect, authorizeAdmin, changeUserPasswordByAdmin);
    router.get('/admin/users/blocked', protect, authorizeAdmin, getBlockedUsers); // Listar contas bloqueadas

    // Gerenciamento de Configurações Administrativas / Promoções
    router.get('/admin/config', protect, authorizeAdmin, getAdminConfig);
    router.put('/admin/config', protect, authorizeAdmin, updateAdminConfig);

    // --- Rota Interna para Tarefas Agendadas (CRON) ---
    // ATENÇÃO: Esta rota deve ser rigorosamente protegida em produção.
    // Considere usar uma chave de API secreta, IP whitelist ou JWT específico para CRON jobs.
    // Para fins de demonstração, vamos protegê-la com admin auth, mas não é o ideal para CRON real.
    // Um CRON job não deveria logar como admin de usuário normal.
    router.post('/internal/process-daily-profits', protect, authorizeAdmin, processDailyProfitsAndCommissions);
    // Idealmente, você teria um mecanismo como:
    // router.post('/internal/process-daily-profits', verifyInternalApiKey, processDailyProfitsAndCommissions);


    // Conecta todas as rotas definidas com o prefixo /api
    app.use('/api', router);
};

module.exports = { appRoutes };