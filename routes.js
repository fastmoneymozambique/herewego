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
    upgradeInvestment,
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
    getDepositConfig,
    getAdminLogs,
} = require('./controllers'); // Importa todos os controladores

const { protect, authorizeAdmin } = require('./middleware'); // Importa os middlewares de segurança
const { upload, uploadToCloudinary } = require('./uploadMiddleware'); // Importa middlewares de upload

const router = express.Router(); // Cria uma instância de router do Express

/**
 * @function appRoutes
 * @description Configura todas as rotas da aplicação no objeto Express 'app'.
 * @param {object} app - A instância do aplicativo Express.
 */
const appRoutes = (app) => {
    
    // --- Rotas de Autenticação e Usuário (Públicas) ---
    router.post('/register', registerUser);
    router.post('/login', loginUser);
    
    // --- Rotas de Usuário Logado (Privadas - Protect) ---
    router.get('/profile', protect, getUserProfile); 
    
    // Configurações de depósito para o Checkout (Público para facilitar o carregamento)
    router.get('/deposit-config', getDepositConfig);

    // --- Rotas de Planos de Investimento (Leitura Pública) ---
    router.get('/investmentplans', getInvestmentPlans); 
    router.get('/investmentplans/:id', getInvestmentPlanById); 

    // --- Rotas de Investimento do Usuário (Privadas) ---
    router.post('/investments', protect, activateInvestment); 
    router.post('/investments/upgrade', protect, upgradeInvestment); 
    router.get('/investments/active', protect, getUserActiveInvestments); 
    router.get('/investments/history', protect, getUserInvestmentHistory); 

    // --- Rotas de Depósito do Usuário (Privadas) ---
    router.post('/deposits', protect, requestDeposit); 
    router.get('/deposits/history', protect, getUserDeposits); 

    // --- Rotas de Saque do Usuário (Privadas) ---
    router.post('/withdrawals', protect, requestWithdrawal); 
    router.get('/withdrawals/history', protect, getUserWithdrawals); 

    // --- Rotas do Painel Administrativo (Exigem Autenticação e Autorização de Admin) ---

    // Gerenciamento de Planos de Investimento (CRUD)
    router.get('/admin/investmentplans', protect, authorizeAdmin, getInvestmentPlans); 
    router.post('/admin/investmentplans', 
        protect, 
        authorizeAdmin, 
        upload.single('image'), 
        uploadToCloudinary, 
        createInvestmentPlan
    );
    router.put('/admin/investmentplans/:id', 
        protect, 
        authorizeAdmin, 
        upload.single('image'), 
        uploadToCloudinary, 
        updateInvestmentPlan
    );
    router.delete('/admin/investmentplans/:id', protect, authorizeAdmin, deleteInvestmentPlan);

    // Gerenciamento de Depósitos Administrativo
    router.get('/admin/deposits/pending', protect, authorizeAdmin, getPendingDeposits);
    router.put('/admin/deposits/:id/approve', protect, authorizeAdmin, approveDeposit);
    router.put('/admin/deposits/:id/reject', protect, authorizeAdmin, rejectDeposit);

    // Gerenciamento de Saques Administrativo
    router.get('/admin/withdrawals/pending', protect, authorizeAdmin, getPendingWithdrawals);
    router.put('/admin/withdrawals/:id/approve', protect, authorizeAdmin, approveWithdrawal);
    router.put('/admin/withdrawals/:id/reject', protect, authorizeAdmin, rejectWithdrawal);

    // Gerenciamento de Usuários Administrativo
    // NOTA: Rotas estáticas como '/blocked' devem vir ANTES das rotas dinâmicas como '/:id'
    router.get('/admin/users/blocked', protect, authorizeAdmin, getBlockedUsers); 
    router.get('/admin/users', protect, authorizeAdmin, getAllUsers); 
    router.get('/admin/users/:id', protect, authorizeAdmin, getUserDetails); 
    router.put('/admin/users/:id/block', protect, authorizeAdmin, blockUser);
    router.put('/admin/users/:id/unblock', protect, authorizeAdmin, unblockUser);
    router.post('/admin/users/create-admin', protect, authorizeAdmin, createAdmin); 
    router.put('/admin/users/:id/change-password', protect, authorizeAdmin, changeUserPasswordByAdmin);
    
    // Logs de Atividade do Admin
    router.get('/admin/logs/admin-actions', protect, authorizeAdmin, getAdminLogs); 

    // Configurações Globais do Sistema (Comissões, Limites, Horários)
    router.get('/admin/config', protect, authorizeAdmin, getAdminConfig);
    router.put('/admin/config', protect, authorizeAdmin, updateAdminConfig);

    // --- Rotas Internas para Tarefas Agendadas (CRON) ---
    // Alterado para GET para permitir que serviços externos (cron-job.org) chamem a URL facilmente
    router.get('/internal/process-daily-profits', processDailyProfitsAndCommissions);
    router.post('/internal/process-daily-profits', processDailyProfitsAndCommissions);

    // Conecta todas as rotas definidas ao aplicativo Express com o prefixo /api
    app.use('/api', router);
};

module.exports = { appRoutes };