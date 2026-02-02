// controllers.js
// Este arquivo contém toda a lógica de negócio (controladores) para as rotas da API.
// Ele interage com os modelos do MongoDB para realizar operações no banco de dados.

const { User, InvestmentPlan, Investment, Deposit, Withdrawal, AdminConfig } = require('./models');
const { logInfo, logError, logAdminAction, generateReferralCode } = require('./utils');
const bcrypt = require('bcryptjs'); // Para comparar senhas em login

// --- Funções Auxiliares Internas ---

/**
 * Gera um token JWT e o envia como cookie e JSON.
 * @param {object} user - O objeto de usuário Mongoose.
 * @param {number} statusCode - O status HTTP da resposta.
 * @param {object} res - O objeto de resposta Express.
 */
const sendTokenResponse = (user, statusCode, res) => {
    const token = user.getSignedJwtToken();

    const options = {
        expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRE * 24 * 60 * 60 * 1000), // Converte dias para milissegundos
        httpOnly: true, // O cookie não pode ser acessado via JavaScript no navegador
        secure: process.env.NODE_ENV === 'production', // Apenas HTTPS em produção
        sameSite: 'strict', // Proteção contra CSRF
    };

    res.status(statusCode).cookie('token', token, options).json({
        success: true,
        token,
        user: {
            _id: user._id,
            phoneNumber: user.phoneNumber,
            balance: user.balance,
            bonusBalance: user.bonusBalance,
            isAdmin: user.isAdmin,
            status: user.status,
            referralCode: user.referralCode,
            invitedBy: user.invitedBy,
            visitorId: user.visitorId,
        }
    });
};

/**
 * Cria o admin inicial se nenhum admin existir.
 * Esta função é chamada uma única vez na inicialização do server.js.
 */
const createInitialAdmin = async () => {
    try {
        const adminExists = await User.findOne({ isAdmin: true });
        if (!adminExists) {
            // Verifica se um usuário com o número de telefone 848441231 já existe para evitar erro de visitorId único
            const existingUserWithPhoneNumber = await User.findOne({ phoneNumber: '848441231' });

            if (existingUserWithPhoneNumber) {
                // Se o número de telefone já existe, e o admin ainda não foi criado (adminExists === false),
                // isso significa uma inconsistência ou uma tentativa anterior falha.
                logError('Tentativa de criar admin inicial, mas um usuário com o número de telefone 848441231 já existe e não é admin. Por favor, remova ou use outro número para o admin inicial.', { existingUserId: existingUserWithPhoneNumber._id });
                return; // Impede a criação se o número já estiver em uso.
            }

            const initialAdmin = await User.create({
                phoneNumber: '848441231',
                password: '147258', // Será hashed automaticamente pelo middleware 'pre save' do schema
                isAdmin: true,
                status: 'active',
                visitorId: 'initialAdminFingerprint', // Fingerprint dummy para o admin inicial
                referralCode: generateReferralCode(),
            });
            logInfo('Admin inicial criado com sucesso: 848441231 / 147258');
        } else {
            logInfo('Admin inicial já existe. Pulando a criação.');
        }

        // Garante que existe uma configuração AdminConfig, independentemente de já haver admin
        let adminConfig = await AdminConfig.findOne();
        if (!adminConfig) {
            adminConfig = await AdminConfig.create({}); // Cria com defaults
            logInfo('AdminConfig inicial criada.');
        } else {
            logInfo('AdminConfig já existe.');
        }

    } catch (error) {
        if (error.code === 11000) { // Erro de duplicidade (visitorId ou phoneNumber)
            logError(`Erro ao criar admin inicial: Já existe um usuário com o mesmo Visitor ID ou número de telefone.`, { error: error.message });
        } else {
            logError(`Erro inesperado ao criar admin inicial: ${error.message}`, { stack: error.stack });
        }
    }
};


// --- User Controllers ---

/**
 * @desc    Registrar um novo usuário
 * @route   POST /api/register
 * @access  Public
 */
const registerUser = async (req, res) => {
    const { phoneNumber, password, visitorId, invitedBy } = req.body;

    // 1. Validação básica de entrada
    if (!phoneNumber || !password || !visitorId) {
        return res.status(400).json({ message: 'Por favor, forneça número de telefone, senha e visitorId.' });
    }

    // 2. Validação do número de telefone (já está no schema, mas é bom pré-validar para feedback rápido)
    if (!/^\d{9}$/.test(phoneNumber)) {
        return res.status(400).json({ message: 'Número de telefone inválido. Deve ter 9 dígitos.' });
    }

    try {
        // 3. Detecção de VisitorId Duplicado e Bloqueio
        const existingUsersWithSameVisitorId = await User.find({ visitorId });

        if (existingUsersWithSameVisitorId.length > 0) {
            // Bloqueia todas as contas associadas a este visitorId, incluindo a nova tentativa
            for (const user of existingUsersWithSameVisitorId) {
                if (user.status === 'active') { // Bloqueia apenas se estiver ativa
                    user.status = 'blocked';
                    await user.save();
                    logAdminAction('SYSTEM', `Conta bloqueada automaticamente por visitorId duplicado.`, { userId: user._id, visitorId: visitorId });
                }
            }
            logError(`Tentativa de registro com visitorId duplicado: ${visitorId}. Contas associadas bloqueadas.`, { phoneNumber, visitorId });
            return res.status(403).json({ message: 'Este dispositivo já foi usado para criar uma conta. Todas as contas associadas foram bloqueadas. Entre em contato com o suporte.' });
        }

        // 4. Checar se o número de telefone já está registrado
        const userExists = await User.findOne({ phoneNumber });
        if (userExists) {
            return res.status(400).json({ message: 'Número de telefone já registrado.' });
        }

        // 5. Gerar Referral Code
        let referralCode = generateReferralCode();
        let codeExists = await User.findOne({ referralCode });
        // Garante que o código de referência é único
        while (codeExists) {
            referralCode = generateReferralCode();
            codeExists = await User.findOne({ referralCode });
        }

        // 6. Processar Indicação (invitedBy)
        let invitingUser = null;
        if (invitedBy) {
            invitingUser = await User.findOne({ referralCode: invitedBy });

            if (invitingUser) {
                // Previne auto-indicação e indicação entre contas com o mesmo visitorId
                if (invitingUser.visitorId === visitorId) {
                    logError(`Tentativa de auto-indicação ou indicação entre contas do mesmo dispositivo.`, { inviterId: invitingUser._id, inviteePhoneNumber: phoneNumber, visitorId });
                    return res.status(400).json({ message: 'Não é possível se indicar ou indicar contas do mesmo dispositivo.' });
                }
                // Adiciona o novo usuário à lista de referidos do convidante
                // Será preenchido com o _id do novo usuário após a criação
            } else {
                logInfo(`Código de indicação inválido: ${invitedBy} para ${phoneNumber}`);
            }
        }

        // 7. Criar o novo usuário
        const newUser = await User.create({
            phoneNumber,
            password,
            visitorId,
            referralCode,
            invitedBy: invitingUser ? invitingUser.referralCode : null, // Armazena o código de indicação do convidante
        });

        if (invitingUser) {
            // Agora que newUser._id existe, podemos adicioná-lo
            invitingUser.referredUsers.push(newUser._id);
            await invitingUser.save();
            logInfo(`Usuário ${newUser.phoneNumber} registrado e referido por ${invitingUser.phoneNumber}.`, { inviterId: invitingUser._id, inviteeId: newUser._id });
        }

        logInfo(`Novo usuário registrado: ${phoneNumber}`, { userId: newUser._id, visitorId });
        sendTokenResponse(newUser, 201, res);

    } catch (error) {
        if (error.code === 11000) { // Erro de duplicidade
            return res.status(400).json({ message: 'Número de telefone ou Visitor ID já está em uso.' });
        }
        logError(`Erro no registro do usuário: ${error.message}`, { stack: error.stack, phoneNumber });
        res.status(500).json({ message: 'Erro ao registrar usuário.' });
    }
};

/**
 * @desc    Autenticar usuário e obter token
 * @route   POST /api/login
 * @access  Public
 */
const loginUser = async (req, res) => {
    const { phoneNumber, password } = req.body;
    const ipAddress = req.ip || req.connection.remoteAddress; // Captura o IP

    if (!phoneNumber || !password) {
        return res.status(400).json({ message: 'Por favor, forneça número de telefone e senha.' });
    }

    try {
        const user = await User.findOne({ phoneNumber }).select('+password'); // Seleciona a senha para comparação

        if (!user) {
            return res.status(401).json({ message: 'Credenciais inválidas.' });
        }

        // Verifica status da conta
        if (user.status === 'blocked') {
            logError(`Tentativa de login em conta bloqueada: ${phoneNumber}`, { userId: user._id });
            return res.status(403).json({ message: 'Sua conta está bloqueada. Entre em contato com o suporte.' });
        }

        const isMatch = await user.matchPassword(password);

        if (!isMatch) {
            return res.status(401).json({ message: 'Credenciais inválidas.' });
        }

        // Atualiza informações de login
        user.lastLoginIp = ipAddress;
        user.lastLoginAt = new Date();
        await user.save();

        logInfo(`Usuário logado: ${phoneNumber}`, { userId: user._id, lastLoginIp: ipAddress });
        sendTokenResponse(user, 200, res);

    } catch (error) {
        logError(`Erro no login do usuário: ${error.message}`, { stack: error.stack, phoneNumber });
        res.status(500).json({ message: 'Erro ao fazer login.' });
    }
};

/**
 * @desc    Obter perfil do usuário logado
 * @route   GET /api/profile
 * @access  Private (User)
 */
const getUserProfile = async (req, res) => {
    try {
        // CORREÇÃO: Garante que 'createdAt' está no select do referredUsers para a página Equipe
        const user = await User.findById(req.user._id)
            .populate({ // População aninhada para obter o nome do plano de investimento
                path: 'activeInvestments',
                populate: {
                    path: 'planId', // Popula o 'planId' dentro de cada 'activeInvestment'
                    select: 'name'  // Seleciona apenas o campo 'name' do plano
                }
            })
            .populate('depositHistory')
            .populate('withdrawalHistory')
            .populate('referredUsers', 'phoneNumber status createdAt'); // ADICIONADO: createdAt para a página Equipe

        if (!user) {
            return res.status(404).json({ message: 'Usuário não encontrado.' });
        }

        res.status(200).json({
            success: true,
            user: {
                _id: user._id,
                phoneNumber: user.phoneNumber,
                balance: user.balance,
                bonusBalance: user.bonusBalance,
                status: user.status,
                visitorId: user.visitorId,
                referralCode: user.referralCode,
                invitedBy: user.invitedBy,
                activeInvestments: user.activeInvestments, // Agora inclui o nome do plano
                depositHistory: user.depositHistory,
                withdrawalHistory: user.withdrawalHistory,
                referredUsers: user.referredUsers,
                createdAt: user.createdAt,
            }
        });
    } catch (error) {
        logError(`Erro ao obter perfil do usuário: ${error.message}`, { stack: error.stack, userId: req.user._id });
        res.status(500).json({ message: 'Erro ao obter perfil do usuário.' });
    }
};

// --- Investment Plan Controllers (Admin) ---

/**
 * @desc    Criar novo plano de investimento
 * @route   POST /api/admin/investmentplans
 * @access  Private (Admin)
 */
const createInvestmentPlan = async (req, res) => {
    const { name, minAmount, maxAmount, dailyProfitRate } = req.body;

    if (!name || !minAmount || !maxAmount || !dailyProfitRate) {
        return res.status(400).json({ message: 'Por favor, forneça nome, valor mínimo, valor máximo e taxa de lucro diário.' });
    }
    if (minAmount < 0 || maxAmount < 0 || dailyProfitRate < 0 || dailyProfitRate > 1) {
        return res.status(400).json({ message: 'Valores inválidos para plano de investimento.' });
    }
    if (minAmount > maxAmount) {
        return res.status(400).json({ message: 'Valor mínimo não pode ser maior que o valor máximo.' });
    }

    try {
        const plan = await InvestmentPlan.create({
            name,
            minAmount,
            maxAmount,
            dailyProfitRate,
        });

        logAdminAction(req.user._id, `Plano de investimento criado: ${name}`, { planId: plan._id });
        res.status(201).json({ success: true, plan });
    } catch (error) {
        if (error.code === 11000) {
            return res.status(400).json({ message: 'Já existe um plano com este nome.' });
        }
        logError(`Erro ao criar plano de investimento: ${error.message}`, { stack: error.stack, adminId: req.user._id });
        res.status(500).json({ message: 'Erro ao criar plano de investimento.' });
    }
};


/**
 * @desc    Obter todos os planos de investimento
 * @route   GET /api/investmentplans
 * @access  Public
 */
const getInvestmentPlans = async (req, res) => {
    try {
        // Se a requisição veio de um usuário autenticado E for admin, 
        // ele verá todos os planos (ativos e inativos).
        // Se for anônimo (req.user é undefined), ou usuário normal, verá apenas os ativos.
        const filter = (req.user && req.user.isAdmin) ? {} : { isActive: true };
        
        const plans = await InvestmentPlan.find(filter).sort({ minAmount: 1 });
        res.status(200).json({ success: true, plans });
    } catch (error) {
        logError(`Erro ao obter planos de investimento: ${error.message}`, { stack: error.stack });
        res.status(500).json({ message: 'Erro ao obter planos de investimento.' });
    }
};


/**
 * @desc    Obter um plano de investimento por ID
 * @route   GET /api/investmentplans/:id
 * @access  Public
 */
const getInvestmentPlanById = async (req, res) => {
    try {
        const plan = await InvestmentPlan.findById(req.params.id);
        if (!plan) {
            return res.status(404).json({ message: 'Plano de investimento não encontrado.' });
        }
        res.status(200).json({ success: true, plan });
    } catch (error) {
        logError(`Erro ao obter plano de investimento por ID: ${error.message}`, { stack: error.stack, planId: req.params.id });
        res.status(500).json({ message: 'Erro ao obter plano de investimento.' });
    }
};

/**
 * @desc    Atualizar um plano de investimento (Admin)
 * @route   PUT /api/admin/investmentplans/:id
 * @access  Private (Admin)
 */
const updateInvestmentPlan = async (req, res) => {
    const { name, minAmount, maxAmount, dailyProfitRate, isActive } = req.body;

    try {
        let plan = await InvestmentPlan.findById(req.params.id);
        if (!plan) {
            return res.status(404).json({ message: 'Plano de investimento não encontrado.' });
        }

        // Validações
        if (minAmount !== undefined && minAmount < 0) return res.status(400).json({ message: 'Valor mínimo inválido.' });
        if (maxAmount !== undefined && maxAmount < 0) return res.status(400).json({ message: 'Valor máximo inválido.' });
        if (dailyProfitRate !== undefined && (dailyProfitRate < 0 || dailyProfitRate > 1)) return res.status(400).json({ message: 'Taxa de lucro diário inválida.' });
        if (minAmount !== undefined && maxAmount !== undefined && minAmount > maxAmount) {
            return res.status(400).json({ message: 'Valor mínimo não pode ser maior que o valor máximo.' });
        }

        plan.name = name !== undefined ? name : plan.name;
        plan.minAmount = minAmount !== undefined ? minAmount : plan.minAmount;
        plan.maxAmount = maxAmount !== undefined ? maxAmount : plan.maxAmount;
        plan.dailyProfitRate = dailyProfitRate !== undefined ? dailyProfitRate : plan.dailyProfitRate;
        plan.isActive = isActive !== undefined ? isActive : plan.isActive;

        await plan.save();

        logAdminAction(req.user._id, `Plano de investimento atualizado: ${plan.name}`, { planId: plan._id });
        res.status(200).json({ success: true, plan });
    } catch (error) {
        if (error.code === 11000) {
            return res.status(400).json({ message: 'Já existe um plano com este nome.' });
        }
        logError(`Erro ao atualizar plano de investimento: ${error.message}`, { stack: error.stack, adminId: req.user._id, planId: req.params.id });
        res.status(500).json({ message: 'Erro ao atualizar plano de investimento.' });
    }
};

/**
 * @desc    Deletar um plano de investimento (Admin)
 * @route   DELETE /api/admin/investmentplans/:id
 * @access  Private (Admin)
 */
const deleteInvestmentPlan = async (req, res) => {
    try {
        const plan = await InvestmentPlan.findById(req.params.id);
        if (!plan) {
            return res.status(404).json({ message: 'Plano de investimento não encontrado.' });
        }

        // TODO: Adicionar lógica para verificar se há investimentos ativos com este plano.
        // Se houver, talvez desativar em vez de deletar ou exigir que não haja investimentos ativos.
        const activeInvestmentsUsingPlan = await Investment.countDocuments({ planId: plan._id, status: 'active' });
        if (activeInvestmentsUsingPlan > 0) {
            return res.status(400).json({ message: 'Não é possível deletar um plano com investimentos ativos. Desative-o primeiro.' });
        }

        await plan.deleteOne();

        logAdminAction(req.user._id, `Plano de investimento deletado: ${plan.name}`, { planId: plan._id });
        res.status(200).json({ success: true, message: 'Plano de investimento removido.' });
    } catch (error) {
        logError(`Erro ao deletar plano de investimento: ${error.message}`, { stack: error.stack, adminId: req.user._id, planId: req.params.id });
        res.status(500).json({ message: 'Erro ao deletar plano de investimento.' });
    }
};

// --- User Investment Controllers ---

/**
 * @desc    Ativar um novo investimento para o usuário
 * @route   POST /api/investments
 * @access  Private (User)
 */
const activateInvestment = async (req, res) => {
    const { planId, amount } = req.body;
    const userId = req.user._id;

    if (!planId || !amount) {
        return res.status(400).json({ message: 'Por favor, forneça o ID do plano e o valor a investir.' });
    }
    if (amount <= 0) {
        return res.status(400).json({ message: 'O valor do investimento deve ser positivo.' });
    }

    try {
        const user = await User.findById(userId);
        const plan = await InvestmentPlan.findById(planId);

        if (!user || !plan || !plan.isActive) {
            return res.status(404).json({ message: 'Usuário ou plano de investimento não encontrado/ativo.' });
        }

        if (amount < plan.minAmount || amount > plan.maxAmount) {
            return res.status(400).json({ message: `O valor do investimento deve estar entre ${plan.minAmount} e ${plan.maxAmount}.` });
        }

        if (user.balance < amount) {
            return res.status(400).json({ message: 'Saldo insuficiente para este investimento.' });
        }

        // Deduzir o valor do saldo do usuário
        user.balance -= amount;

        // Calcular data de término (60 dias a partir de agora)
        const endDate = new Date();
        endDate.setDate(endDate.getDate() + plan.durationDays);

        // Criar o registro de investimento
        const investment = await Investment.create({
            userId,
            planId,
            investedAmount: amount,
            dailyProfitRate: plan.dailyProfitRate,
            endDate: endDate,
        });

        // Adicionar o investimento ativo ao usuário
        user.activeInvestments.push(investment._id);
        await user.save();

        logInfo(`Novo investimento ativado por ${user.phoneNumber} no plano ${plan.name} com ${amount} MT.`, { userId, investmentId: investment._id });

        // Lógica de comissão para o convidante (se houver)
        const adminConfig = await AdminConfig.findOne();
        if (adminConfig && adminConfig.isPromotionActive && user.invitedBy) {
            const inviter = await User.findOne({ referralCode: user.invitedBy });
            if (inviter && inviter._id.toString() !== user._id.toString() && inviter.visitorId !== user.visitorId) { // Evita auto-comissão e comissão de mesmo dispositivo
                // Comissão por ativação de plano (valor único)
                if (adminConfig.commissionOnPlanActivation > 0) {
                    const commissionAmount = amount * adminConfig.commissionOnPlanActivation;
                    inviter.bonusBalance += commissionAmount;
                    await inviter.save();
                    logInfo(`Comissão de ativação de plano (${commissionAmount} MT) creditada para o convidante ${inviter.phoneNumber}.`, { inviterId: inviter._id, inviteeId: user._id, commissionAmount });
                }

                // A comissão sobre renda diária será tratada pela tarefa agendada
            }
        }


        res.status(201).json({ success: true, message: 'Investimento ativado com sucesso!', investment });

    } catch (error) {
        logError(`Erro ao ativar investimento para o usuário ${userId}: ${error.message}`, { stack: error.stack, userId });
        res.status(500).json({ message: 'Erro ao ativar investimento.' });
    }
};

/**
 * @desc    Obter todos os investimentos ativos do usuário logado
 * @route   GET /api/investments/active
 * @access  Private (User)
 */
const getUserActiveInvestments = async (req, res) => {
    try {
        const investments = await Investment.find({ userId: req.user._id, status: 'active' })
            .populate('planId', 'name dailyProfitRate durationDays'); // Popula detalhes do plano

        res.status(200).json({ success: true, investments });
    } catch (error) {
        logError(`Erro ao obter investimentos ativos do usuário: ${error.message}`, { stack: error.stack, userId: req.user._id });
        res.status(500).json({ message: 'Erro ao obter investimentos ativos.' });
    }
};

/**
 * @desc    Obter todo o histórico de investimentos do usuário logado
 * @route   GET /api/investments/history
 * @access  Private (User)
 */
const getUserInvestmentHistory = async (req, res) => {
    try {
        const investments = await Investment.find({ userId: req.user._id })
            .populate('planId', 'name dailyProfitRate durationDays')
            .sort({ createdAt: -1 });

        res.status(200).json({ success: true, investments });
    } catch (error) {
        logError(`Erro ao obter histórico de investimentos do usuário: ${error.message}`, { stack: error.stack, userId: req.user._id });
        res.status(500).json({ message: 'Erro ao obter histórico de investimentos.' });
    }
};

// --- Deposit Controllers ---

/**
 * @desc    Usuário solicita um depósito
 * @route   POST /api/deposits
 * @access  Private (User)
 */
const requestDeposit = async (req, res) => {
    const { amount, confirmationMessage } = req.body;
    const userId = req.user._id;

    if (!amount || !confirmationMessage) {
        return res.status(400).json({ message: 'Por favor, forneça o valor e a mensagem de confirmação do depósito.' });
    }
    // O Frontend já está validando, mas a API deve validar o mínimo também
    const adminConfig = await AdminConfig.findOne();
    const minDeposit = adminConfig ? adminConfig.minDepositAmount : 50; 

    if (amount < minDeposit) {
        return res.status(400).json({ message: `O valor do depósito deve ser no mínimo ${minDeposit} MT.` });
    }

    try {
        const deposit = await Deposit.create({
            userId,
            amount,
            confirmationMessage,
            status: 'pending',
        });

        // Adiciona o depósito ao histórico do usuário
        const user = await User.findById(userId);
        user.depositHistory.push(deposit._id);
        await user.save();

        logInfo(`Solicitação de depósito criada por ${user.phoneNumber} no valor de ${amount} MT.`, { userId, depositId: deposit._id, confirmationMessage });
        res.status(201).json({ success: true, message: 'Solicitação de depósito enviada para aprovação.', deposit });
    } catch (error) {
        logError(`Erro ao solicitar depósito para o usuário ${userId}: ${error.message}`, { stack: error.stack, userId });
        res.status(500).json({ message: 'Erro ao solicitar depósito.' });
    }
};

/**
 * @desc    Obter histórico de depósitos do usuário logado
 * @route   GET /api/deposits/history
 * @access  Private (User)
 */
const getUserDeposits = async (req, res) => {
    try {
        // Embora o /api/profile já popule, esta rota é mais limpa para o histórico de depósito puro
        const deposits = await Deposit.find({ userId: req.user._id }).sort({ requestDate: -1 });
        res.status(200).json({ success: true, deposits });
    } catch (error) {
        logError(`Erro ao obter depósitos do usuário: ${error.message}`, { stack: error.stack, userId: req.user._id });
        res.status(500).json({ message: 'Erro ao obter depósitos.' });
    }
};

/**
 * @desc    Obter todos os depósitos pendentes (Admin)
 * @route   GET /api/admin/deposits/pending
 * @access  Private (Admin)
 */
const getPendingDeposits = async (req, res) => {
    try {
        const pendingDeposits = await Deposit.find({ status: 'pending' })
            .populate('userId', 'phoneNumber visitorId')
            .sort({ requestDate: 1 });

        res.status(200).json({ success: true, deposits: pendingDeposits });
    } catch (error) {
        logError(`Erro ao obter depósitos pendentes: ${error.message}`, { stack: error.stack, adminId: req.user._id });
        res.status(500).json({ message: 'Erro ao obter depósitos pendentes.' });
    }
};

/**
 * @desc    Aprovar um depósito (Admin)
 * @route   PUT /api/admin/deposits/:id/approve
 * @access  Private (Admin)
 */
const approveDeposit = async (req, res) => {
    try {
        const deposit = await Deposit.findById(req.params.id);

        if (!deposit) {
            return res.status(404).json({ message: 'Depósito não encontrado.' });
        }
        if (deposit.status !== 'pending') {
            return res.status(400).json({ message: 'Este depósito não está pendente de aprovação.' });
        }

        deposit.status = 'approved';
        deposit.approvalDate = new Date();
        deposit.adminId = req.user._id;
        await deposit.save();

        const user = await User.findById(deposit.userId);
        if (user) {
            user.balance += deposit.amount;
            await user.save();
            logInfo(`Saldo do usuário ${user.phoneNumber} creditado com ${deposit.amount} MT.`, { userId: user._id, depositId: deposit._id });
        }

        logAdminAction(req.user._id, `Depósito aprovado para o usuário ${user ? user.phoneNumber : 'N/A'}.`, { depositId: deposit._id, amount: deposit.amount });
        res.status(200).json({ success: true, message: 'Depósito aprovado com sucesso.', deposit });

    } catch (error) {
        logError(`Erro ao aprovar depósito: ${error.message}`, { stack: error.stack, adminId: req.user._id, depositId: req.params.id });
        res.status(500).json({ message: 'Erro ao aprovar depósito.' });
    }
};

/**
 * @desc    Rejeitar um depósito (Admin)
 * @route   PUT /api/admin/deposits/:id/reject
 * @access  Private (Admin)
 */
const rejectDeposit = async (req, res) => {
    try {
        const deposit = await Deposit.findById(req.params.id);

        if (!deposit) {
            return res.status(404).json({ message: 'Depósito não encontrado.' });
        }
        if (deposit.status !== 'pending') {
            return res.status(400).json({ message: 'Este depósito não está pendente de rejeição.' });
        }

        deposit.status = 'rejected';
        deposit.approvalDate = new Date(); // Pode ser a data da rejeição
        deposit.adminId = req.user._id;
        await deposit.save();

        const user = await User.findById(deposit.userId); // Apenas para logging
        logAdminAction(req.user._id, `Depósito rejeitado para o usuário ${user ? user.phoneNumber : 'N/A'}.`, { depositId: deposit._id, amount: deposit.amount });
        res.status(200).json({ success: true, message: 'Depósito rejeitado com sucesso.', deposit });

    } catch (error) {
        logError(`Erro ao rejeitar depósito: ${error.message}`, { stack: error.stack, adminId: req.user._id, depositId: req.params.id });
        res.status(500).json({ message: 'Erro ao rejeitar depósito.' });
    }
};

// --- Withdrawal Controllers ---

/**
 * @desc    Usuário solicita um saque
 * @route   POST /api/withdrawals
 * @access  Private (User)
 */
const requestWithdrawal = async (req, res) => {
    const { amount, walletAddress } = req.body; // walletAddress contém Nome, Telefone e Método de Pagamento
    const userId = req.user._id;

    if (!amount || !walletAddress) {
        return res.status(400).json({ message: 'Por favor, forneça o valor e o endereço da carteira/detalhes de pagamento para saque.' });
    }
    // O Frontend já está validando, mas a API deve validar o mínimo (1 MT)
    if (amount <= 0) {
        return res.status(400).json({ message: 'O valor do saque deve ser positivo.' });
    }

    try {
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ message: 'Usuário não encontrado.' });
        }

        if (user.balance < amount) {
            return res.status(400).json({ message: 'Saldo insuficiente para este saque.' });
        }

        // Deduzir o valor do saldo imediatamente, o status será pendente
        user.balance -= amount;

        const withdrawal = await Withdrawal.create({
            userId,
            amount,
            walletAddress, // Detalhes de pagamento consolidados
            status: 'pending',
        });

        // Adiciona o saque ao histórico do usuário
        user.withdrawalHistory.push(withdrawal._id);
        await user.save();

        logInfo(`Solicitação de saque criada por ${user.phoneNumber} no valor de ${amount} MT. Detalhes: ${walletAddress}`, { userId, withdrawalId: withdrawal._id });
        res.status(201).json({ success: true, message: 'Solicitação de saque enviada para aprovação.', withdrawal });
    } catch (error) {
        logError(`Erro ao solicitar saque para o usuário ${userId}: ${error.message}`, { stack: error.stack, userId });
        res.status(500).json({ message: 'Erro ao solicitar saque.' });
    }
};

/**
 * @desc    Obter histórico de saques do usuário logado
 * @route   GET /api/withdrawals/history
 * @access  Private (User)
 */
const getUserWithdrawals = async (req, res) => {
    try {
        const withdrawals = await Withdrawal.find({ userId: req.user._id }).sort({ requestDate: -1 });
        res.status(200).json({ success: true, withdrawals });
    } catch (error) {
        logError(`Erro ao obter saques do usuário: ${error.message}`, { stack: error.stack, userId: req.user._id });
        res.status(500).json({ message: 'Erro ao obter saques.' });
    }
};

/**
 * @desc    Obter todos os saques pendentes (Admin)
 * @route   GET /api/admin/withdrawals/pending
 * @access  Private (Admin)
 */
const getPendingWithdrawals = async (req, res) => {
    try {
        const pendingWithdrawals = await Withdrawal.find({ status: 'pending' })
            .populate('userId', 'phoneNumber visitorId')
            .sort({ requestDate: 1 });

        res.status(200).json({ success: true, withdrawals: pendingWithdrawals });
    } catch (error) {
        logError(`Erro ao obter saques pendentes: ${error.message}`, { stack: error.stack, adminId: req.user._id });
        res.status(500).json({ message: 'Erro ao obter saques pendentes.' });
    }
};

/**
 * @desc    Aprovar um saque (Admin)
 * @route   PUT /api/admin/withdrawals/:id/approve
 * @access  Private (Admin)
 */
const approveWithdrawal = async (req, res) => {
    try {
        const withdrawal = await Withdrawal.findById(req.params.id);

        if (!withdrawal) {
            return res.status(404).json({ message: 'Saque não encontrado.' });
        }
        if (withdrawal.status !== 'pending') {
            return res.status(400).json({ message: 'Este saque não está pendente de aprovação.' });
        }

        withdrawal.status = 'approved';
        withdrawal.approvalDate = new Date();
        withdrawal.adminId = req.user._id;
        await withdrawal.save();

        const user = await User.findById(withdrawal.userId); // Apenas para logging
        logAdminAction(req.user._id, `Saque aprovado para o usuário ${user ? user.phoneNumber : 'N/A'}.`, { withdrawalId: withdrawal._id, amount: withdrawal.amount });
        res.status(200).json({ success: true, message: 'Saque aprovado com sucesso.', withdrawal });

    } catch (error) {
        logError(`Erro ao aprovar saque: ${error.message}`, { stack: error.stack, adminId: req.user._id, withdrawalId: req.params.id });
        res.status(500).json({ message: 'Erro ao aprovar saque.' });
    }
};

/**
 * @desc    Rejeitar um saque (Admin)
 * @route   PUT /api/admin/withdrawals/:id/reject
 * @access  Private (Admin)
 */
const rejectWithdrawal = async (req, res) => {
    try {
        const withdrawal = await Withdrawal.findById(req.params.id);

        if (!withdrawal) {
            return res.status(404).json({ message: 'Saque não encontrado.' });
        }
        if (withdrawal.status !== 'pending') {
            return res.status(400).json({ message: 'Este saque não está pendente de rejeição.' });
        }

        withdrawal.status = 'rejected';
        withdrawal.approvalDate = new Date(); // Pode ser a data da rejeição
        withdrawal.adminId = req.user._id;
        await withdrawal.save();

        // Se o saque for rejeitado, o valor deve ser creditado de volta ao saldo do usuário
        const user = await User.findById(withdrawal.userId);
        if (user) {
            user.balance += withdrawal.amount;
            await user.save();
            logInfo(`Valor de ${withdrawal.amount} MT creditado de volta ao usuário ${user.phoneNumber} devido a saque rejeitado.`, { userId: user._id, withdrawalId: withdrawal._id });
        }

        logAdminAction(req.user._id, `Saque rejeitado para o usuário ${user ? user.phoneNumber : 'N/A'}.`, { withdrawalId: withdrawal._id, amount: withdrawal.amount });
        res.status(200).json({ success: true, message: 'Saque rejeitado com sucesso. Valor devolvido ao saldo do usuário.', withdrawal });

    } catch (error) {
        logError(`Erro ao rejeitar saque: ${error.message}`, { stack: error.stack, adminId: req.user._id, withdrawalId: req.params.id });
        res.status(500).json({ message: 'Erro ao rejeitar saque.' });
    }
};

// --- Admin Panel Controllers ---

/**
 * @desc    Obter configurações de depósito (M-Pesa/Emola)
 * @route   GET /api/deposit-config
 * @access  Public (Usado pelo Frontend para o Checkout)
 */
const getDepositConfig = async (req, res) => {
    try {
        const config = await AdminConfig.findOne().select('minDepositAmount mpesaDepositNumber mpesaRecipientName emolaDepositNumber emolaRecipientName commissionOnDailyProfit');
        
        if (!config) {
            // Se não houver config, cria uma com valores padrão antes de retornar
            const newConfig = await AdminConfig.create({});
            logInfo('AdminConfig não encontrada, uma nova foi criada com valores padrão.');
            return res.status(200).json({ success: true, config: newConfig });
        }

        res.status(200).json({ success: true, config });
    } catch (error) {
        logError(`Erro ao obter configurações de depósito: ${error.message}`, { stack: error.stack });
        res.status(500).json({ message: 'Erro ao obter configurações de depósito.' });
    }
};


/**
 * @desc    Obter todas as configurações de promoção (Admin)
 * @route   GET /api/admin/config
 * @access  Private (Admin)
 */
const getAdminConfig = async (req, res) => {
    try {
        const config = await AdminConfig.findOne();
        if (!config) {
            // Se não houver config, crie uma com valores padrão
            const newConfig = await AdminConfig.create({});
            logInfo('AdminConfig não encontrada, uma nova foi criada com valores padrão.');
            return res.status(200).json({ success: true, config: newConfig });
        }
        res.status(200).json({ success: true, config });
    } catch (error) {
        logError(`Erro ao obter configurações administrativas: ${error.message}`, { stack: error.stack, adminId: req.user._id });
        res.status(500).json({ message: 'Erro ao obter configurações administrativas.' });
    }
};


/**
 * @desc    Atualizar configurações de promoção (Admin)
 * @route   PUT /api/admin/config
 * @access  Private (Admin)
 */
const updateAdminConfig = async (req, res) => {
    const { isPromotionActive, referralBonusAmount, referralRequiredInvestedCount, commissionOnPlanActivation, commissionOnDailyProfit, minDepositAmount, mpesaDepositNumber, mpesaRecipientName, emolaDepositNumber, emolaRecipientName } = req.body;

    try {
        let config = await AdminConfig.findOne(); // Busca a única instância
        if (!config) {
            config = await AdminConfig.create({});
            logInfo('AdminConfig criada durante tentativa de atualização, pois não existia.');
        }

        // Configurações de Promoção
        config.isPromotionActive = isPromotionActive !== undefined ? isPromotionActive : config.isPromotionActive;
        config.referralBonusAmount = referralBonusAmount !== undefined ? referralBonusAmount : config.referralBonusAmount;
        config.referralRequiredInvestedCount = referralRequiredInvestedCount !== undefined ? referralRequiredInvestedCount : config.referralRequiredInvestedCount;
        config.commissionOnPlanActivation = commissionOnPlanActivation !== undefined ? commissionOnPlanActivation : config.commissionOnPlanActivation;
        config.commissionOnDailyProfit = commissionOnDailyProfit !== undefined ? commissionOnDailyProfit : config.commissionOnDailyProfit;

        // Configurações de Depósito (Novas)
        config.minDepositAmount = minDepositAmount !== undefined ? minDepositAmount : config.minDepositAmount;
        config.mpesaDepositNumber = mpesaDepositNumber !== undefined ? mpesaDepositNumber : config.mpesaDepositNumber;
        config.mpesaRecipientName = mpesaRecipientName !== undefined ? mpesaRecipientName : config.mpesaRecipientName;
        config.emolaDepositNumber = emolaDepositNumber !== undefined ? emolaDepositNumber : config.emolaDepositNumber;
        config.emolaRecipientName = emolaRecipientName !== undefined ? emolaRecipientName : config.emolaRecipientName;


        await config.save();

        logAdminAction(req.user._id, `Configurações administrativas atualizadas.`, { configId: config._id, updatedFields: req.body });
        res.status(200).json({ success: true, message: 'Configurações administrativas atualizadas com sucesso.', config });
    } catch (error) {
        logError(`Erro ao atualizar configurações de promoção: ${error.message}`, { stack: error.stack, adminId: req.user._id });
        res.status(500).json({ message: 'Erro ao atualizar configurações de promoção.' });
    }
};


/**
 * @desc    Obter todos os usuários (Admin)
 * @route   GET /api/admin/users
 * @access  Private (Admin)
 */
const getAllUsers = async (req, res) => {
    try {
        // CORREÇÃO FINAL: Seleciona explicitamente os campos que o frontend precisa e exclui a senha
        const users = await User.find({})
                                .select('_id phoneNumber status isAdmin referralCode invitedBy createdAt')
                                .sort({ createdAt: -1 });

        res.status(200).json({ success: true, users });
    } catch (error) {
        logError(`Erro ao obter todos os usuários: ${error.message}`, { stack: error.stack, adminId: req.user._id });
        res.status(500).json({ message: 'Erro ao obter usuários.' });
    }
};

/**
 * @desc    Obter detalhes de um único usuário (Admin)
 * @route   GET /api/admin/users/:id
 * @access  Private (Admin)
 */
const getUserDetails = async (req, res) => {
    try {
        const user = await User.findById(req.params.id)
            .select('-password')
            .populate('activeInvestments')
            .populate('depositHistory')
            .populate('withdrawalHistory')
            .populate('referredUsers', 'phoneNumber status');

        if (!user) {
            return res.status(404).json({ message: 'Usuário não encontrado.' });
        }
        res.status(200).json({ success: true, user });
    } catch (error) {
        logError(`Erro ao obter detalhes do usuário ${req.params.id}: ${error.message}`, { stack: error.stack, adminId: req.user._id });
        res.status(500).json({ message: 'Erro ao obter detalhes do usuário.' });
    }
};

/**
 * @desc    Bloquear uma conta de usuário (Admin)
 * @route   PUT /api/admin/users/:id/block
 * @access  Private (Admin)
 */
const blockUser = async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('-password');
        if (!user) {
            return res.status(404).json({ message: 'Usuário não encontrado.' });
        }
        if (user.isAdmin) {
            return res.status(403).json({ message: 'Não é possível bloquear outro administrador.' });
        }

        user.status = 'blocked';
        await user.save();

        logAdminAction(req.user._id, `Usuário bloqueado: ${user.phoneNumber}`, { userId: user._id });
        res.status(200).json({ success: true, message: 'Usuário bloqueado com sucesso.', user });
    } catch (error) {
        logError(`Erro ao bloquear usuário ${req.params.id}: ${error.message}`, { stack: error.stack, adminId: req.user._id });
        res.status(500).json({ message: 'Erro ao bloquear usuário.' });
    }
};

/**
 * @desc    Desbloquear uma conta de usuário (Admin)
 * @route   PUT /api/admin/users/:id/unblock
 * @access  Private (Admin)
 */
const unblockUser = async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('-password');
        if (!user) {
            return res.status(404).json({ message: 'Usuário não encontrado.' });
        }

        user.status = 'active';
        await user.save();

        logAdminAction(req.user._id, `Usuário desbloqueado: ${user.phoneNumber}`, { userId: user._id });
        res.status(200).json({ success: true, message: 'Usuário desbloqueado com sucesso.', user });
    } catch (error) {
        logError(`Erro ao desbloquear usuário ${req.params.id}: ${error.message}`, { stack: error.stack, adminId: req.user._id });
        res.status(500).json({ message: 'Erro ao desbloquear usuário.' });
    }
};

/**
 * @desc    Criar um novo administrador (Admin)
 * @route   POST /api/admin/users/create-admin
 * @access  Private (Admin)
 */
const createAdmin = async (req, res) => {
    const { phoneNumber, password } = req.body;

    if (!phoneNumber || !password) {
        return res.status(400).json({ message: 'Por favor, forneça número de telefone e senha para o novo administrador.' });
    }
    if (!/^\d{9}$/.test(phoneNumber)) {
        return res.status(400).json({ message: 'Número de telefone inválido. Deve ter 9 dígitos.' });
    }

    try {
        const adminExists = await User.findOne({ phoneNumber });
        if (adminExists) {
            return res.status(400).json({ message: 'Um usuário/admin com este número de telefone já existe.' });
        }

        // Criar um visitorId dummy para o novo admin
        const visitorId = `admin_${Date.now()}`;
        const newAdmin = await User.create({
            phoneNumber,
            password,
            isAdmin: true,
            status: 'active',
            visitorId, // Um visitorId único para admins criados manualmente
            referralCode: generateReferralCode(),
        });

        logAdminAction(req.user._id, `Novo administrador criado: ${phoneNumber}`, { newAdminId: newAdmin._id });
        res.status(201).json({ success: true, message: 'Novo administrador criado com sucesso.', admin: { _id: newAdmin._id, phoneNumber: newAdmin.phoneNumber } });
    } catch (error) {
        if (error.code === 11000) {
            return res.status(400).json({ message: 'Número de telefone ou Visitor ID já está em uso.' });
        }
        logError(`Erro ao criar novo administrador: ${error.message}`, { stack: error.stack, adminId: req.user._id, phoneNumber });
        res.status(500).json({ message: 'Erro ao criar novo administrador.' });
    }
};

/**
 * @desc    Alterar a senha de um usuário (Admin)
 * @route   PUT /api/admin/users/:id/change-password
 * @access  Private (Admin)
 */
const changeUserPasswordByAdmin = async (req, res) => {
    const { newPassword } = req.body;

    if (!newPassword || newPassword.length < 6) {
        return res.status(400).json({ message: 'A nova senha deve ter pelo menos 6 caracteres.' });
    }

    try {
        const user = await User.findById(req.params.id);
        if (!user) {
            return res.status(404).json({ message: 'Usuário não encontrado.' });
        }

        // A senha será hashed automaticamente pelo middleware 'pre save'
        user.password = newPassword;
        await user.save(); // Salvar para que o hook de hash seja acionado

        logAdminAction(req.user._id, `Senha do usuário ${user.phoneNumber} alterada.`, { userId: user._id });
        res.status(200).json({ success: true, message: 'Senha do usuário alterada com sucesso.' });
    } catch (error) {
        logError(`Erro ao alterar senha do usuário ${req.params.id} pelo admin: ${error.message}`, { stack: error.stack, adminId: req.user._id });
        res.status(500).json({ message: 'Erro ao alterar senha do usuário.' });
    }
};

/**
 * @desc    Obter contas bloqueadas (Admin)
 * @route   GET /api/admin/users/blocked
 * @access  Private (Admin)
 */
const getBlockedUsers = async (req, res) => {
    try {
        // CORREÇÃO FINAL: Seleciona explicitamente os campos que o frontend precisa e exclui a senha
        // A exclusão de campos como -lastLoginIp ou -lastLoginAt é removida para máxima compatibilidade.
        const blockedUsers = await User.find({ status: 'blocked' })
                                        .select('_id phoneNumber status referralCode invitedBy createdAt') // Campos essenciais
                                        .sort({ createdAt: -1 });

        res.status(200).json({ success: true, users: blockedUsers });
    } catch (error) {
        logError(`Erro ao obter contas bloqueadas: ${error.message}`, { stack: error.stack, adminId: req.user._id });
        res.status(500).json({ message: 'Erro ao obter contas bloqueadas.' });
    }
};

// --- Funções de CRON / Tarefas Agendadas (chamadas por rotas internas/jobs) ---

/**
 * @desc    Processa lucros diários para investimentos ativos e encerra investimentos completos.
 *          Esta função seria idealmente chamada por um CRON job ou serviço agendado.
 * @route   POST /api/internal/process-daily-profits (Protegida por API Key ou IP whitelist em produção)
 * @access  Private (Internal/Scheduled Task)
 */
const processDailyProfitsAndCommissions = async (req, res) => {
    try {
        const today = new Date();
        today.setHours(0, 0, 0, 0); // Considerar o início do dia para cálculo

        const investments = await Investment.find({
            status: 'active',
            lastProfitCreditDate: { $lt: today }, // Apenas investimentos que não tiveram lucro creditado hoje
        }).populate('userId'); // Popula o usuário para atualizar o saldo e verificar convidante

        const adminConfig = await AdminConfig.findOne(); // Para comissões

        logInfo(`Iniciando processamento diário de lucros para ${investments.length} investimentos.`);

        for (const investment of investments) {
            const user = investment.userId; // O usuário já populado

            if (!user || user.status === 'blocked') {
                logInfo(`Ignorando investimento ${investment._id} porque o usuário está bloqueado ou não existe.`, { investmentId: investment._id, userId: user ? user._id : 'N/A' });
                continue;
            }

            // 1. Calcular e creditar lucro diário
            const dailyProfit = investment.investedAmount * investment.dailyProfitRate;
            investment.currentProfit += dailyProfit;
            user.balance += dailyProfit; // Credita no saldo principal

            // 2. Lógica de Comissão sobre Renda Diária para o convidante
            if (adminConfig && adminConfig.isPromotionActive && adminConfig.commissionOnDailyProfit > 0 && user.invitedBy) {
                const inviter = await User.findOne({ referralCode: user.invitedBy });

                // Garante que o convidante existe, não é o mesmo usuário e não é do mesmo dispositivo
                if (inviter && inviter._id.toString() !== user._id.toString() && inviter.visitorId !== user.visitorId) {
                    const commission = dailyProfit * adminConfig.commissionOnDailyProfit;
                    inviter.bonusBalance += commission; // Credita no saldo de bônus do convidante
                    await inviter.save();
                    logInfo(`Comissão diária de ${commission} MT creditada para o convidante ${inviter.phoneNumber}.`, { inviterId: inviter._id, inviteeId: user._id, investmentId: investment._id });
                }
            }

            investment.lastProfitCreditDate = today; // Atualiza a data do último crédito de lucro
            await investment.save();
            await user.save(); // Salva as atualizações no usuário

            logInfo(`Lucro diário de ${dailyProfit} MT creditado para o investimento ${investment._id} do usuário ${user.phoneNumber}. Novo saldo: ${user.balance}.`, { userId: user._id, investmentId: investment._id });

            // 3. Verificar e encerrar investimento se a duração for atingida
            if (investment.endDate <= today) {
                investment.status = 'completed';
                await investment.save();

                // Remover o investimento da lista de ativos do usuário
                user.activeInvestments = user.activeInvestments.filter(id => id.toString() !== investment._id.toString());
                await user.save();

                logInfo(`Investimento ${investment._id} do usuário ${user.phoneNumber} completado.`, { userId: user._id, investmentId: investment._id });
            }
        }

        // 4. Lógica para bônus fixo por número de referidos (ex: convidar 10 investidores -> X MT)
        if (adminConfig && adminConfig.isPromotionActive && adminConfig.referralBonusAmount > 0 && adminConfig.referralRequiredInvestedCount > 0) {
            const usersToCheckForReferralBonus = await User.find({
                'referredUsers.0': { '$exists': true }, // Pelo menos um referido
                // Simplificação: Assumimos que a lógica de bônus está correta.
            }).populate('referredUsers');

            for (const user of usersToCheckForReferralBonus) {
                // Conta quantos referidos deste usuário ativaram um investimento
                const investedReferralsCount = await User.countDocuments({
                    _id: { $in: user.referredUsers.map(ref => ref._id) },
                    activeInvestments: { $exists: true, $not: { $size: 0 } } // Tem pelo menos 1 investimento ativo ou já teve
                });

                // A lógica de checagem do bônus fixo é removida daqui e deve ser refeita em um endpoint Admin
                // ou em uma lógica mais robusta de CRON, pois é muito propensa a erros de dupla creditação.
                // Mantemos o comentário para a sua referência, mas o código de CRON não deve ser complexo.

            }
        }


        logInfo('Processamento diário de lucros concluído.');
        if (res) { // Só envia resposta se for uma requisição HTTP
            res.status(200).json({ success: true, message: 'Processamento diário de lucros e comissões concluído.' });
        }
    } catch (error) {
        logError(`Erro durante o processamento diário de lucros e comissões: ${error.message}`, { stack: error.stack });
        if (res) {
            res.status(500).json({ message: 'Erro durante o processamento diário de lucros e comissões.' });
        }
    }
};


// Exportar todos os controladores
module.exports = {
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
    createInitialAdmin, // Exportado para ser chamado APENAS no server.js
    getDepositConfig, // NOVO: Para obter as configurações de depósito M-Pesa/Emola
};