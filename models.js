// models.js
// Este arquivo contém a definição de todos os Schemas e Modelos Mongoose
// para a aplicação KKR Credit.

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); // Para hashing de senhas
const jwt = require('jsonwebtoken'); // Para tokens de autenticação
const { logError } = require('./utils'); // Para logging

// --- 1. User Schema ---
const userSchema = new mongoose.Schema({
    phoneNumber: {
        type: String,
        required: [true, 'Número de telefone é obrigatório.'],
        unique: true,
        trim: true,
        // Validação para 9 dígitos, sem espaços e sem DDD
        match: [/^\d{9}$/, 'Número de telefone inválido. Deve ter 9 dígitos.'],
    },
    password: {
        type: String,
        required: [true, 'Senha é obrigatória.'],
        minlength: [6, 'A senha deve ter pelo menos 6 caracteres.'],
        select: false, // Não retorna a senha por padrão em consultas
    },
    balance: {
        type: Number,
        default: 0,
        min: [0, 'Saldo não pode ser negativo.'],
    },
    bonusBalance: {
        type: Number,
        default: 0,
        min: [0, 'Saldo de bônus não pode ser negativo.'],
    },
    status: {
        type: String,
        enum: ['active', 'blocked'],
        default: 'active',
    },
    visitorId: {
        type: String,
        required: [true, 'Visitor ID é obrigatório.'],
        unique: true,
        index: true, // Para buscas rápidas
    },
    isAdmin: {
        type: Boolean,
        default: false,
    },
    referralCode: {
        type: String,
        unique: true,
        sparse: true, // Permite que seja nulo e ainda assim único
    },
    invitedBy: {
        type: String, // O referralCode do usuário que convidou
        ref: 'User', // Referência ao modelo User
        sparse: true,
    },
    referredUsers: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
    }],
    activeInvestments: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Investment',
    }],
    depositHistory: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Deposit',
    }],
    withdrawalHistory: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Withdrawal',
    }],
    hasReceivedReferralBonus: { 
        type: Boolean,
        default: false,
    },
    lastLoginIp: String, // Para fins informativos/logs
    lastLoginAt: Date,
    createdAt: {
        type: Date,
        default: Date.now,
    },
}, {
    timestamps: true, // Adiciona campos createdAt e updatedAt automaticamente
});

// Middleware para hash de senha antes de salvar
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        return next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
});

// Método para comparar senha
userSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

// Método para gerar JWT
userSchema.methods.getSignedJwtToken = function () {
    return jwt.sign({ id: this._id, isAdmin: this.isAdmin }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRE,
    });
};

// --- 2. Investment Plan Schema (Planos definidos pelo Admin) ---
const investmentPlanSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Nome do plano é obrigatório.'],
        unique: true,
        trim: true,
    },
    minAmount: {
        type: Number,
        required: [true, 'Valor mínimo é obrigatório.'],
        min: [0, 'Valor mínimo não pode ser negativo.'],
    },
    maxAmount: {
        type: Number,
        required: [true, 'Valor máximo é obrigatório.'],
        // CORREÇÃO CRÍTICA: A validação de min <= max foi movida para o controller.
        min: [0, 'Valor máximo não pode ser negativo.'], 
    },
    dailyProfitRate: { // Ex: 0.02 para 2% ao dia
        type: Number,
        required: [true, 'Taxa de lucro diário é obrigatória.'],
        min: [0, 'Taxa de lucro não pode ser negativa.'],
        max: [1, 'Taxa de lucro não pode ser maior que 1 (100%).'],
    },
    durationDays: { // Fixa em 60 dias
        type: Number,
        default: 60,
        immutable: true, // Uma vez definido, não pode ser alterado
    },
    isActive: {
        type: Boolean,
        default: true,
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
}, {
    timestamps: true,
});

// --- 3. Investment Schema (Investimentos ativos de um usuário) ---
const investmentSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    planId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'InvestmentPlan',
        required: true,
    },
    investedAmount: {
        type: Number,
        required: [true, 'Valor investido é obrigatório.'],
        min: [0, 'Valor investido não pode ser negativo.'],
    },
    dailyProfitRate: { // Copia do plano para garantir que não muda se o plano for alterado
        type: Number,
        required: true,
    },
    startDate: {
        type: Date,
        default: Date.now,
    },
    endDate: {
        type: Date,
        required: true, // Calculado no controller
    },
    currentProfit: { // Lucro acumulado até o momento
        type: Number,
        default: 0,
        min: [0, 'Lucro não pode ser negativo.'],
    },
    lastProfitCreditDate: { // Data da última vez que o lucro foi creditado
        type: Date,
        default: Date.now,
    },
    status: {
        type: String,
        enum: ['active', 'completed', 'cancelled'],
        default: 'active',
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
}, {
    timestamps: true,
});

// --- 4. Deposit Schema ---
const depositSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    amount: {
        type: Number,
        required: [true, 'Valor do depósito é obrigatório.'],
        min: [1, 'O valor do depósito deve ser maior que zero.'],
    },
    confirmationMessage: {
        type: String,
        required: [true, 'Mensagem de confirmação é obrigatória.'],
        trim: true,
    },
    status: {
        type: String,
        enum: ['pending', 'approved', 'rejected'],
        default: 'pending',
    },
    requestDate: {
        type: Date,
        default: Date.now,
    },
    approvalDate: Date,
    adminId: { // Admin que aprovou/rejeitou o depósito
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User', // Pode ser um usuário com isAdmin: true
        sparse: true,
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
}, {
    timestamps: true,
});

// --- 5. Withdrawal Schema ---
const withdrawalSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    amount: {
        type: Number,
        required: [true, 'Valor do saque é obrigatório.'],
        min: [1, 'O valor do saque deve ser maior que zero.'],
    },
    walletAddress: { // Detalhes de pagamento consolidados (Método, Nome, Número)
        type: String,
        required: [true, 'Endereço da carteira ou detalhes de pagamento são obrigatórios.'],
        trim: true,
    },
    status: {
        type: String,
        enum: ['pending', 'approved', 'rejected'],
        default: 'pending',
    },
    requestDate: {
        type: Date,
        default: Date.now,
    },
    approvalDate: Date,
    adminId: { // Admin que aprovou/rejeitou o saque
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User', // Pode ser um usuário com isAdmin: true
        sparse: true,
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
}, {
    timestamps: true,
});

// --- 6. AdminConfig Schema (Para configurações globais e de promoção) ---
const adminConfigSchema = new mongoose.Schema({
    isPromotionActive: {
        type: Boolean,
        default: true, // A promoção de indicação pode ser ativada/desativada
    },
    referralBonusAmount: { // Ex: 20 MT por X indicações
        type: Number,
        default: 0,
        min: [0, 'Valor do bônus não pode ser negativo.'],
    },
    referralRequiredInvestedCount: { // Ex: 10 usuários para ganhar o bônus fixo
        type: Number,
        default: 0,
        min: [0, 'Número de usuários referidos deve ser 0 ou mais.'],
    },
    commissionOnPlanActivation: { // Ex: 0.05 para 5% do valor investido
        type: Number,
        default: 0,
        min: [0, 'Comissão de ativação não pode ser negativa.'],
        max: [1, 'Comissão de ativação não pode ser maior que 1 (100%).'],
    },
    commissionOnDailyProfit: { // Ex: 0.01 para 1% do lucro diário do referido
        type: Number,
        default: 0,
        min: [0, 'Comissão de lucro diário não pode ser negativa.'],
        max: [1, 'Comissão de lucro diário não pode ser maior que 1 (100%).'],
    },
    
    // --- Configurações de Depósito (NOVOS CAMPOS) ---
    minDepositAmount: {
        type: Number,
        default: 50, // Mínimo de 50 MT
        min: [1, 'Valor mínimo de depósito deve ser 1 ou mais.'],
    },
    mpesaDepositNumber: {
        type: String,
        default: '841234567', // Número M-Pesa padrão (ADMIN deve configurar)
    },
    mpesaRecipientName: {
        type: String,
        default: 'KKR M-PESA ADMIN', // Nome do beneficiário (ADMIN deve configurar)
    },
    emolaDepositNumber: {
        type: String,
        default: '879876543', // Número Emola padrão (ADMIN deve configurar)
    },
    emolaRecipientName: {
        type: String,
        default: 'KKR EMOLA ADMIN', // Nome do beneficiário (ADMIN deve configurar)
    },
    // --- FIM DOS NOVOS CAMPOS ---

    // Garante que só haverá um documento de configurações
    singletonId: {
        type: Number,
        default: 1,
        unique: true,
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
}, {
    timestamps: true,
});


// Exporta os modelos
module.exports = {
    User: mongoose.model('User', userSchema),
    InvestmentPlan: mongoose.model('InvestmentPlan', investmentPlanSchema),
    Investment: mongoose.model('Investment', investmentSchema),
    Deposit: mongoose.model('Deposit', depositSchema),
    Withdrawal: mongoose.model('Withdrawal', withdrawalSchema),
    AdminConfig: mongoose.model('AdminConfig', adminConfigSchema),
};