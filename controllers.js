// controllers.js
// Este arquivo contém toda a lógica de negócio (controladores) para as rotas da API.
// Ele interage com os modelos do MongoDB para realizar operações no banco de dados.

const { User, InvestmentPlan, Investment, Deposit, Withdrawal, AdminConfig } = require('./models');
const { logInfo, logError, logAdminAction, generateReferralCode } = require('./utils');
const bcrypt = require('bcryptjs'); // Para comparar senhas em login
const fs = require('fs'); // Para ler arquivos de log
const path = require('path'); // Para resolver caminhos de arquivo

// Caminho para o arquivo de log de ações administrativas
const ADMIN_ACTION_LOG_FILE = path.join(__dirname, 'logs', 'admin_actions.log');


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
            totalCommissionEarned: user.totalCommissionEarned,
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
 */
const createInitialAdmin = async () => {
    try {
        const adminExists = await User.findOne({ isAdmin: true });
        if (!adminExists) {
            const existingUserWithPhoneNumber = await User.findOne({ phoneNumber: '848441231' });

            if (existingUserWithPhoneNumber) {
                logError('Tentativa de criar admin inicial, mas um usuário com o número de telefone 848441231 já existe e não é admin.');
                return; 
            }

            const initialAdmin = await User.create({
                phoneNumber: '848441231',
                password: '147258', 
                isAdmin: true,
                status: 'active',
                visitorId: 'initialAdminFingerprint', 
                referralCode: generateReferralCode(),
            });
            logInfo('Admin inicial criado com sucesso: 848441231 / 147258');
        } else {
            logInfo('Admin inicial já existe. Pulando a criação.');
        }

        let adminConfig = await AdminConfig.findOne();
        if (!adminConfig) {
            adminConfig = await AdminConfig.create({}); 
            logInfo('AdminConfig inicial criada.');
        }

    } catch (error) {
        logError(`Erro inesperado ao criar admin inicial: ${error.message}`);
    }
};

// --- User Controllers ---

const registerUser = async (req, res) => {
    const { phoneNumber, password, visitorId, inviteCode } = req.body;

    if (!phoneNumber || !password || !visitorId) {
        return res.status(400).json({ message: 'Por favor, forneça número de telefone, senha e visitorId.' });
    }

    if (!/^\d{9}$/.test(phoneNumber)) {
        return res.status(400).json({ message: 'Número de telefone inválido. Deve ter 9 dígitos.' });
    }

    try {
        const existingUsersWithSameVisitorId = await User.find({ visitorId });

        if (existingUsersWithSameVisitorId.length > 0) {
            for (const user of existingUsersWithSameVisitorId) {
                if (user.status === 'active') {
                    user.status = 'blocked';
                    await user.save();
                    logAdminAction('SYSTEM', `Conta bloqueada automaticamente por visitorId duplicado.`, { userId: user._id, visitorId: visitorId });
                }
            }
            return res.status(403).json({ message: 'Este dispositivo já foi usado para criar uma conta. Todas as contas associadas foram bloqueadas.' });
        }

        const userExists = await User.findOne({ phoneNumber });
        if (userExists) {
            return res.status(400).json({ message: 'Número de telefone já registrado.' });
        }

        let referralCode = generateReferralCode();
        let codeExists = await User.findOne({ referralCode });
        while (codeExists) {
            referralCode = generateReferralCode();
            codeExists = await User.findOne({ referralCode });
        }

        let invitingUser = null;
        if (inviteCode) {
            invitingUser = await User.findOne({ referralCode: inviteCode });
            if (invitingUser && invitingUser.visitorId === visitorId) {
                invitingUser = null; 
            }
        }

        const newUser = await User.create({
            phoneNumber,
            password,
            visitorId,
            referralCode,
            invitedBy: invitingUser ? invitingUser.referralCode : null,
        });

        if (invitingUser) {
            invitingUser.referredUsers.push(newUser._id);
            await invitingUser.save();
        }

        logInfo(`Novo usuário registrado: ${phoneNumber}`);
        sendTokenResponse(newUser, 201, res);

    } catch (error) {
        logError(`Erro no registro: ${error.message}`);
        res.status(500).json({ message: 'Erro ao registrar usuário.' });
    }
};

const loginUser = async (req, res) => {
    const { phoneNumber, password } = req.body;
    const ipAddress = req.ip || req.connection.remoteAddress;

    if (!phoneNumber || !password) {
        return res.status(400).json({ message: 'Por favor, forneça número de telefone e senha.' });
    }

    try {
        const user = await User.findOne({ phoneNumber }).select('+password');

        if (!user) {
            return res.status(401).json({ message: 'Credenciais inválidas.' });
        }

        if (user.status === 'blocked') {
            return res.status(403).json({ message: 'Sua conta está bloqueada.' });
        }

        const isMatch = await user.matchPassword(password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Credenciais inválidas.' });
        }

        user.lastLoginIp = ipAddress;
        user.lastLoginAt = new Date();
        await user.save();

        sendTokenResponse(user, 200, res);

    } catch (error) {
        logError(`Erro no login: ${error.message}`);
        res.status(500).json({ message: 'Erro ao fazer login.' });
    }
};

const getUserProfile = async (req, res) => {
    try {
        const user = await User.findById(req.user._id)
            .populate({ 
                path: 'activeInvestments',
                populate: { path: 'planId', select: 'name' }
            })
            .populate('depositHistory')
            .populate('withdrawalHistory')
            .populate('referredUsers', 'phoneNumber status createdAt'); 

        if (!user) {
            return res.status(404).json({ message: 'Usuário não encontrado.' });
        }

        res.status(200).json({
            success: true,
            user: {
                _id: user._id,
                phoneNumber: user.phoneNumber,
                balance: user.balance,
                totalCommissionEarned: user.totalCommissionEarned,
                status: user.status,
                visitorId: user.visitorId,
                referralCode: user.referralCode,
                invitedBy: user.invitedBy,
                activeInvestments: user.activeInvestments, 
                depositHistory: user.depositHistory,
                withdrawalHistory: user.withdrawalHistory,
                referredUsers: user.referredUsers,
                createdAt: user.createdAt,
                lastLoginAt: user.lastLoginAt, 
            }
        });
    } catch (error) {
        logError(`Erro ao obter perfil: ${error.message}`);
        res.status(500).json({ message: 'Erro ao obter perfil.' });
    }
};

// --- Investment Plan Controllers (Admin) ---

const createInvestmentPlan = async (req, res) => {
    const { name, minAmount, dailyProfitRate } = req.body;
    const uploadedImageUrl = req.uploadedImageUrl; 

    if (!name || !minAmount || !dailyProfitRate) {
        return res.status(400).json({ message: 'Por favor, forneça nome, valor mínimo e taxa de lucro diário.' });
    }
    
    const maxAmount = minAmount; 

    try {
        const plan = await InvestmentPlan.create({
            name,
            minAmount,
            maxAmount,
            dailyProfitRate,
            imageUrl: uploadedImageUrl || req.body.imageUrl || 'https://res.cloudinary.com/default-image-url', 
        });

        logAdminAction(req.user._id, `Plano criado: ${name}`);
        res.status(201).json({ success: true, plan });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao criar plano.' });
    }
};

const getInvestmentPlans = async (req, res) => {
    try {
        const filter = (req.user && req.user.isAdmin) ? {} : { isActive: true };
        const plans = await InvestmentPlan.find(filter).sort({ minAmount: 1 });
        res.status(200).json({ success: true, plans });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao obter planos.' });
    }
};

const getInvestmentPlanById = async (req, res) => {
    try {
        const plan = await InvestmentPlan.findById(req.params.id);
        if (!plan) return res.status(404).json({ message: 'Plano não encontrado.' });
        res.status(200).json({ success: true, plan });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao obter plano.' });
    }
};

const updateInvestmentPlan = async (req, res) => {
    const uploadedImageUrl = req.uploadedImageUrl; 
    const { name, minAmount, dailyProfitRate, isActive, imageUrl } = req.body;

    try {
        let plan = await InvestmentPlan.findById(req.params.id);
        if (!plan) return res.status(404).json({ message: 'Plano não encontrado.' });

        plan.name = name !== undefined ? name : plan.name;
        plan.minAmount = minAmount !== undefined ? minAmount : plan.minAmount;
        plan.maxAmount = plan.minAmount; 
        plan.dailyProfitRate = dailyProfitRate !== undefined ? dailyProfitRate : plan.dailyProfitRate;
        plan.isActive = isActive !== undefined ? isActive : plan.isActive;
        
        if (uploadedImageUrl) {
            plan.imageUrl = uploadedImageUrl;
        } else if (imageUrl !== undefined) { 
             plan.imageUrl = imageUrl;
        }

        await plan.save();
        res.status(200).json({ success: true, plan });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao atualizar plano.' });
    }
};

const deleteInvestmentPlan = async (req, res) => {
    try {
        const plan = await InvestmentPlan.findById(req.params.id);
        if (!plan) return res.status(404).json({ message: 'Plano não encontrado.' });

        const activeInvestmentsUsingPlan = await Investment.countDocuments({ planId: plan._id, status: 'active' });
        if (activeInvestmentsUsingPlan > 0) {
            return res.status(400).json({ message: 'Não é possível deletar um plano com investimentos ativos.' });
        }

        await InvestmentPlan.findByIdAndDelete(req.params.id);
        res.status(200).json({ success: true, message: 'Plano removido.' });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao deletar plano.' });
    }
};

// --- User Investment Controllers ---

const activateInvestment = async (req, res) => {
    const { planId } = req.body; 
    const userId = req.user._id;

    try {
        const user = await User.findById(userId);
        const plan = await InvestmentPlan.findById(planId);
        const adminConfig = await AdminConfig.findOne();

        if (!user || !plan || !plan.isActive) {
            return res.status(404).json({ message: 'Plano não encontrado ou inativo.' });
        }
        
        if (user.activeInvestments && user.activeInvestments.length > 0) {
             return res.status(400).json({ message: 'Você já possui um investimento ativo. Use o Upgrade.' });
        }
        
        if (user.balance < plan.minAmount) {
            return res.status(400).json({ message: 'Saldo insuficiente.' });
        }

        user.balance -= plan.minAmount;

        const endDate = new Date();
        endDate.setDate(endDate.getDate() + plan.durationDays);

        const investment = await Investment.create({
            userId,
            planId,
            investedAmount: plan.minAmount, 
            dailyProfitRate: plan.dailyProfitRate,
            endDate: endDate,
            lastProfitCreditDate: new Date() // O primeiro dia já conta como creditado (ou o ciclo começa amanhã)
        });

        user.activeInvestments.push(investment._id);
        await user.save();
        
        // Comissão de Ativação
        if (user.invitedBy && adminConfig && adminConfig.commissionOnPlanActivation > 0) {
            const inviter = await User.findOne({ referralCode: user.invitedBy, status: 'active' });
            if (inviter) {
                const commissionAmount = plan.minAmount * adminConfig.commissionOnPlanActivation;
                inviter.balance += commissionAmount;
                inviter.totalCommissionEarned += commissionAmount;
                await inviter.save();
            }
        }

        res.status(201).json({ success: true, message: 'Investimento ativado!', investment });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao ativar investimento.' });
    }
};

const upgradeInvestment = async (req, res) => {
    const { newPlanId } = req.body;
    const userId = req.user._id;

    try {
        const user = await User.findById(userId);
        const newPlan = await InvestmentPlan.findById(newPlanId);

        if (!user || !newPlan || !newPlan.isActive) {
            return res.status(404).json({ message: 'Novo plano não encontrado.' });
        }

        const activeInvestment = await Investment.findById(user.activeInvestments[0]).populate('planId'); 
        if (!activeInvestment) return res.status(400).json({ message: 'Nenhum investimento ativo encontrado.' });

        const priceDifference = newPlan.minAmount - activeInvestment.investedAmount;
        if (priceDifference <= 0) return res.status(400).json({ message: 'O novo plano deve ser mais caro.' });

        if (user.balance < priceDifference) return res.status(400).json({ message: 'Saldo insuficiente para upgrade.' });

        user.balance -= priceDifference;
        activeInvestment.planId = newPlan._id;
        activeInvestment.investedAmount = newPlan.minAmount;
        activeInvestment.dailyProfitRate = newPlan.dailyProfitRate;
        
        const newEndDate = new Date();
        newEndDate.setDate(newEndDate.getDate() + newPlan.durationDays);
        activeInvestment.endDate = newEndDate;
        activeInvestment.lastProfitCreditDate = new Date(); 
        
        await activeInvestment.save();
        await user.save();

        res.status(200).json({ success: true, message: 'Upgrade concluído!', investment: activeInvestment });
    } catch (error) {
        res.status(500).json({ message: 'Erro no upgrade.' });
    }
};

const getUserActiveInvestments = async (req, res) => {
    try {
        const investments = await Investment.find({ userId: req.user._id, status: 'active' }).populate('planId');
        res.status(200).json({ success: true, investments });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao obter ativos.' });
    }
};

const getUserInvestmentHistory = async (req, res) => {
    try {
        const investments = await Investment.find({ userId: req.user._id }).populate('planId').sort({ createdAt: -1 });
        res.status(200).json({ success: true, investments });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao obter histórico.' });
    }
};

// --- Deposit Controllers ---

const requestDeposit = async (req, res) => {
    const { amount, confirmationMessage } = req.body;
    const userId = req.user._id;

    try {
        const adminConfig = await AdminConfig.findOne();
        if (amount < (adminConfig?.minDepositAmount || 50)) {
            return res.status(400).json({ message: 'Valor abaixo do mínimo.' });
        }

        const deposit = await Deposit.create({ userId, amount, confirmationMessage });
        const user = await User.findById(userId);
        user.depositHistory.push(deposit._id);
        await user.save();

        res.status(201).json({ success: true, message: 'Solicitação enviada.', deposit });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao depositar.' });
    }
};

const getUserDeposits = async (req, res) => {
    try {
        const deposits = await Deposit.find({ userId: req.user._id }).sort({ requestDate: -1 });
        res.status(200).json({ success: true, deposits });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao obter depósitos.' });
    }
};

const getPendingDeposits = async (req, res) => {
    try {
        const deposits = await Deposit.find({ status: 'pending' }).populate('userId', 'phoneNumber');
        res.status(200).json({ success: true, deposits });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao obter pendentes.' });
    }
};

const approveDeposit = async (req, res) => {
    try {
        const deposit = await Deposit.findById(req.params.id);
        if (!deposit || deposit.status !== 'pending') return res.status(400).json({ message: 'Inválido.' });

        deposit.status = 'approved';
        deposit.approvalDate = new Date();
        deposit.adminId = req.user._id;
        await deposit.save();

        const user = await User.findById(deposit.userId);
        user.balance += deposit.amount;
        await user.save();

        res.status(200).json({ success: true, message: 'Aprovado.' });
    } catch (error) {
        res.status(500).json({ message: 'Erro.' });
    }
};

const rejectDeposit = async (req, res) => {
    try {
        const deposit = await Deposit.findById(req.params.id);
        if (!deposit || deposit.status !== 'pending') return res.status(400).json({ message: 'Inválido.' });

        deposit.status = 'rejected';
        deposit.adminId = req.user._id;
        await deposit.save();

        res.status(200).json({ success: true, message: 'Rejeitado.' });
    } catch (error) {
        res.status(500).json({ message: 'Erro.' });
    }
};

// --- Withdrawal Controllers ---

const isWithdrawalTimeAllowed = (startTime, endTime) => {
    const now = new Date();
    const currentHour = now.getHours();
    const currentMinute = now.getMinutes();

    const parseTime = (timeStr) => {
        const [hour, minute] = timeStr.split(':').map(Number);
        return hour * 60 + minute;
    };

    const currentTimeInMinutes = currentHour * 60 + currentMinute;
    return currentTimeInMinutes >= parseTime(startTime) && currentTimeInMinutes <= parseTime(endTime);
};

const requestWithdrawal = async (req, res) => {
    const { amount, walletAddress } = req.body;
    const userId = req.user._id;

    try {
        const user = await User.findById(userId);
        const config = await AdminConfig.findOne();

        if (config && !isWithdrawalTimeAllowed(config.withdrawalStartTime, config.withdrawalEndTime)) {
            return res.status(400).json({ message: 'Fora do horário de saque.' });
        }

        if (amount < config.minWithdrawalAmount || amount > config.maxWithdrawalAmount) {
            return res.status(400).json({ message: 'Valor fora dos limites.' });
        }

        if (user.balance < amount) return res.status(400).json({ message: 'Saldo insuficiente.' });

        user.balance -= amount;
        const withdrawal = await Withdrawal.create({ userId, amount, walletAddress });
        user.withdrawalHistory.push(withdrawal._id);
        await user.save();

        res.status(201).json({ success: true, message: 'Saque solicitado.', withdrawal });
    } catch (error) {
        res.status(500).json({ message: 'Erro.' });
    }
};

const getUserWithdrawals = async (req, res) => {
    try {
        const withdrawals = await Withdrawal.find({ userId: req.user._id }).sort({ requestDate: -1 });
        res.status(200).json({ success: true, withdrawals });
    } catch (error) {
        res.status(500).json({ message: 'Erro.' });
    }
};

const getPendingWithdrawals = async (req, res) => {
    try {
        const withdrawals = await Withdrawal.find({ status: 'pending' }).populate('userId', 'phoneNumber');
        res.status(200).json({ success: true, withdrawals });
    } catch (error) {
        res.status(500).json({ message: 'Erro.' });
    }
};

const approveWithdrawal = async (req, res) => {
    try {
        const withdrawal = await Withdrawal.findById(req.params.id);
        if (!withdrawal || withdrawal.status !== 'pending') return res.status(400).json({ message: 'Inválido.' });

        withdrawal.status = 'approved';
        withdrawal.approvalDate = new Date();
        withdrawal.adminId = req.user._id;
        await withdrawal.save();

        res.status(200).json({ success: true, message: 'Aprovado.' });
    } catch (error) {
        res.status(500).json({ message: 'Erro.' });
    }
};

const rejectWithdrawal = async (req, res) => {
    try {
        const withdrawal = await Withdrawal.findById(req.params.id);
        if (!withdrawal || withdrawal.status !== 'pending') return res.status(400).json({ message: 'Inválido.' });

        withdrawal.status = 'rejected';
        withdrawal.adminId = req.user._id;
        await withdrawal.save();

        const user = await User.findById(withdrawal.userId);
        user.balance += withdrawal.amount;
        await user.save();

        res.status(200).json({ success: true, message: 'Rejeitado e saldo devolvido.' });
    } catch (error) {
        res.status(500).json({ message: 'Erro.' });
    }
};

// --- Admin Panel Controllers ---

const getDepositConfig = async (req, res) => {
    try {
        const config = await AdminConfig.findOne();
        res.status(200).json({ success: true, config });
    } catch (error) {
        res.status(500).json({ message: 'Erro.' });
    }
};

const getAdminConfig = async (req, res) => {
    try {
        const config = await AdminConfig.findOne();
        res.status(200).json({ success: true, config });
    } catch (error) {
        res.status(500).json({ message: 'Erro.' });
    }
};

const updateAdminConfig = async (req, res) => {
    try {
        let config = await AdminConfig.findOne();
        Object.assign(config, req.body);
        await config.save();
        res.status(200).json({ success: true, config });
    } catch (error) {
        res.status(500).json({ message: 'Erro.' });
    }
};

const getAllUsers = async (req, res) => {
    try {
        const users = await User.find({}).select('-password').sort({ createdAt: -1 });
        res.status(200).json({ success: true, users });
    } catch (error) {
        res.status(500).json({ message: 'Erro.' });
    }
};

const getUserDetails = async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('-password')
            .populate('activeInvestments').populate('depositHistory').populate('withdrawalHistory').populate('referredUsers');
        res.status(200).json({ success: true, user });
    } catch (error) {
        res.status(500).json({ message: 'Erro.' });
    }
};

const blockUser = async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (user.isAdmin) return res.status(403).json({ message: 'Não pode bloquear admin.' });
        user.status = 'blocked';
        await user.save();
        res.status(200).json({ success: true, message: 'Bloqueado.' });
    } catch (error) {
        res.status(500).json({ message: 'Erro.' });
    }
};

const unblockUser = async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        user.status = 'active';
        await user.save();
        res.status(200).json({ success: true, message: 'Desbloqueado.' });
    } catch (error) {
        res.status(500).json({ message: 'Erro.' });
    }
};

const createAdmin = async (req, res) => {
    const { phoneNumber, password } = req.body;
    try {
        const newAdmin = await User.create({ phoneNumber, password, isAdmin: true, visitorId: `admin_${Date.now()}` });
        res.status(201).json({ success: true, admin: newAdmin });
    } catch (error) {
        res.status(500).json({ message: 'Erro.' });
    }
};

const changeUserPasswordByAdmin = async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        user.password = req.body.newPassword;
        await user.save();
        res.status(200).json({ success: true, message: 'Senha alterada.' });
    } catch (error) {
        res.status(500).json({ message: 'Erro.' });
    }
};

const getBlockedUsers = async (req, res) => {
    try {
        const users = await User.find({ status: 'blocked' });
        res.status(200).json({ success: true, users });
    } catch (error) {
        res.status(500).json({ message: 'Erro.' });
    }
};

const getAdminLogs = async (req, res) => {
    try {
        if (!fs.existsSync(ADMIN_ACTION_LOG_FILE)) return res.status(200).json({ success: true, logs: [] });
        const data = fs.readFileSync(ADMIN_ACTION_LOG_FILE, 'utf8');
        const logs = data.split('\n').filter(line => line.trim() !== '').reverse();
        res.status(200).json({ success: true, logs });
    } catch (error) {
        res.status(500).json({ message: 'Erro.' });
    }
};

// --- LÓGICA DE RENDA DIÁRIA CORRIGIDA ---

/**
 * @desc    Processa lucros diários e comissões.
 * Esta função foi otimizada para garantir que o lucro caia todos os dias.
 */
const processDailyProfitsAndCommissions = async (req, res) => {
    try {
        const now = new Date();
        // Definimos o início do dia atual (00:00:00) para comparação
        const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());

        // 1. Buscar investimentos ativos que ainda não foram creditados HOJE
        const investments = await Investment.find({
            status: 'active',
            $or: [
                { lastProfitCreditDate: { $lt: startOfToday } },
                { lastProfitCreditDate: { $exists: false } }
            ]
        }).populate('userId');

        const adminConfig = await AdminConfig.findOne();
        const commissionRate = adminConfig ? adminConfig.commissionOnDailyProfit : 0;
        
        logInfo(`Processamento Diário: ${investments.length} pacotes para processar.`);

        let processedCount = 0;

        for (const investment of investments) {
            const user = investment.userId;

            if (!user || user.status === 'blocked') continue;

            // 2. Verificar se o investimento expirou
            if (new Date(investment.endDate) <= now) {
                investment.status = 'completed';
                await investment.save();
                
                // Remove do array de ativos do usuário
                user.activeInvestments = user.activeInvestments.filter(id => id.toString() !== investment._id.toString());
                await user.save();
                continue;
            }

            // 3. Calcular Lucro Diário
            const dailyProfit = investment.investedAmount * investment.dailyProfitRate;

            // 4. Creditar Saldo do Usuário
            user.balance += dailyProfit;
            await user.save();

            // 5. Atualizar o Registro de Investimento
            investment.currentProfit += dailyProfit;
            investment.lastProfitCreditDate = now; // Atualiza para agora, impedindo duplo crédito hoje
            await investment.save();

            // 6. Lógica de Comissão sobre Lucro Diário (Indicação)
            if (commissionRate > 0 && user.invitedBy) {
                const inviter = await User.findOne({ referralCode: user.invitedBy, status: 'active' });
                if (inviter) {
                    const commissionAmount = dailyProfit * commissionRate;
                    inviter.balance += commissionAmount;
                    inviter.totalCommissionEarned += commissionAmount;
                    await inviter.save();
                }
            }

            processedCount++;
        }

        logInfo(`Sucesso: ${processedCount} rendas creditadas hoje.`);
        
        if (res) {
            res.status(200).json({ 
                success: true, 
                message: `Processamento concluído. ${processedCount} usuários receberam lucros.`,
                date: now.toISOString()
            });
        }
    } catch (error) {
        logError(`Falha Crítica no Processamento Diário: ${error.message}`);
        if (res) res.status(500).json({ message: 'Erro interno no processamento.' });
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
    createInitialAdmin, 
    getDepositConfig, 
    getAdminLogs, 
};