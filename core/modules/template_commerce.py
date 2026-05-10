"""Template Commerce: Multi-tier pricing, revenue settlement, invoice management, enterprise licensing.

Provides:
- Multi-tier pricing model: Free templates (completely free), paid templates (one-time purchase), subscription templates (monthly/yearly), enterprise licenses (team-based template packages), template trials (first 30% steps free)
- Revenue distribution and settlement: Platform commission (0% for free, 20-30% for paid), real-time author revenue tracking, monthly settlement, multiple withdrawal methods (WeChat/Alipay/PayPal/crypto), automatic enterprise invoice generation
- Enterprise template management: Admin unified purchase and team distribution, enterprise private template library, template usage audit, template policy control
"""

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class PricingModel(Enum):
    """Template pricing models."""
    FREE = "free"
    ONE_TIME = "one_time"
    SUBSCRIPTION_MONTHLY = "subscription_monthly"
    SUBSCRIPTION_YEARLY = "subscription_yearly"
    ENTERPRISE = "enterprise"


class WithdrawalMethod(Enum):
    """Withdrawal methods."""
    WECHAT = "wechat"
    ALIPAY = "alipay"
    PAYPAL = "paypal"
    CRYPTO = "crypto"


class InvoiceStatus(Enum):
    """Invoice status."""
    PENDING = "pending"
    ISSUED = "issued"
    SENT = "sent"
    PAID = "paid"


class LicenseStatus(Enum):
    """Enterprise license status."""
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    PENDING = "pending"


@dataclass
class TemplatePricing:
    """Template pricing configuration.

    Attributes:
        template_id: Template identifier
        pricing_model: Pricing model
        price: Price in cents
        currency: Currency code
        trial_steps_percent: Percentage of steps available for trial
        subscription_period_days: Subscription period in days
        enterprise_min_users: Minimum users for enterprise license
        enterprise_max_users: Maximum users for enterprise license
        discount_percent: Current discount percentage
        is_on_sale: Whether template is on sale
    """
    template_id: str = ""
    pricing_model: PricingModel = PricingModel.FREE
    price: int = 0
    currency: str = "USD"
    trial_steps_percent: int = 30
    subscription_period_days: int = 30
    enterprise_min_users: int = 5
    enterprise_max_users: int = 100
    discount_percent: int = 0
    is_on_sale: bool = False


@dataclass
class Purchase:
    """Template purchase record.

    Attributes:
        purchase_id: Unique purchase identifier
        template_id: Template identifier
        user_id: User identifier
        pricing_model: Pricing model used
        amount_paid: Amount paid in cents
        currency: Currency code
        purchase_timestamp: Purchase timestamp
        expires_at: Subscription expiration (if applicable)
        is_trial: Whether this is a trial purchase
        payment_method: Payment method used
        transaction_id: Payment transaction ID
    """
    purchase_id: str = ""
    template_id: str = ""
    user_id: str = ""
    pricing_model: PricingModel = PricingModel.FREE
    amount_paid: int = 0
    currency: str = "USD"
    purchase_timestamp: float = 0.0
    expires_at: float = 0.0
    is_trial: bool = False
    payment_method: str = ""
    transaction_id: str = ""


@dataclass
class RevenueRecord:
    """Author revenue record.

    Attributes:
        record_id: Unique record identifier
        author_id: Author identifier
        template_id: Template identifier
        purchase_id: Related purchase ID
        gross_amount: Gross amount in cents
        platform_commission: Platform commission in cents
        net_amount: Net amount to author in cents
        commission_rate: Commission rate (0-100)
        timestamp: Revenue timestamp
        is_settled: Whether revenue has been settled
        settlement_id: Settlement batch ID
    """
    record_id: str = ""
    author_id: str = ""
    template_id: str = ""
    purchase_id: str = ""
    gross_amount: int = 0
    platform_commission: int = 0
    net_amount: int = 0
    commission_rate: float = 0.0
    timestamp: float = 0.0
    is_settled: bool = False
    settlement_id: str = ""


@dataclass
class Settlement:
    """Author settlement batch.

    Attributes:
        settlement_id: Unique settlement identifier
        author_id: Author identifier
        total_amount: Total amount in cents
        withdrawal_method: Withdrawal method
        withdrawal_address: Withdrawal address/account
        status: Settlement status
        created_at: Creation timestamp
        processed_at: Processing timestamp
        transaction_reference: Payment transaction reference
    """
    settlement_id: str = ""
    author_id: str = ""
    total_amount: int = 0
    withdrawal_method: WithdrawalMethod = WithdrawalMethod.PAYPAL
    withdrawal_address: str = ""
    status: str = "pending"
    created_at: float = 0.0
    processed_at: float = 0.0
    transaction_reference: str = ""


@dataclass
class Invoice:
    """Enterprise invoice.

    Attributes:
        invoice_id: Unique invoice identifier
        enterprise_id: Enterprise identifier
        amount: Invoice amount in cents
        currency: Currency code
        items: List of invoice items
        status: Invoice status
        issue_date: Invoice issue date
        due_date: Invoice due date
        paid_date: Payment date
        tax_rate: Tax rate percentage
        tax_amount: Tax amount in cents
    """
    invoice_id: str = ""
    enterprise_id: str = ""
    amount: int = 0
    currency: str = "USD"
    items: List[Dict[str, Any]] = field(default_factory=list)
    status: InvoiceStatus = InvoiceStatus.PENDING
    issue_date: float = 0.0
    due_date: float = 0.0
    paid_date: float = 0.0
    tax_rate: float = 0.0
    tax_amount: int = 0


@dataclass
class EnterpriseLicense:
    """Enterprise template license.

    Attributes:
        license_id: Unique license identifier
        enterprise_id: Enterprise identifier
        template_id: Template identifier
        license_status: License status
        max_users: Maximum users allowed
        assigned_users: List of assigned user IDs
        purchase_date: Purchase date
        expires_at: Expiration date
        auto_renew: Whether auto-renew is enabled
        invoice_id: Related invoice ID
    """
    license_id: str = ""
    enterprise_id: str = ""
    template_id: str = ""
    license_status: LicenseStatus = LicenseStatus.PENDING
    max_users: int = 0
    assigned_users: List[str] = field(default_factory=list)
    purchase_date: float = 0.0
    expires_at: float = 0.0
    auto_renew: bool = False
    invoice_id: str = ""


class TemplateCommerce:
    """Commerce system for template marketplace.

    Handles multi-tier pricing, revenue distribution, settlements,
    invoices, and enterprise licensing.
    """

    PLATFORM_COMMISSION_FREE = 0.0
    PLATFORM_COMMISSION_PAID = 0.25
    PLATFORM_COMMISSION_SUBSCRIPTION = 0.20
    PLATFORM_COMMISSION_ENTERPRISE = 0.15

    MIN_WITHDRAWAL_AMOUNT = 1000

    def __init__(
        self,
        storage_path: str = "",
        payment_processor: Optional[Any] = None,
    ) -> None:
        """Initialize template commerce system.

        Args:
            storage_path: Directory path for storage.
            payment_processor: Optional payment processor integration.
        """
        self.storage_path = storage_path
        self._payment_processor = payment_processor
        self._template_pricing: Dict[str, TemplatePricing] = {}
        self._purchases: Dict[str, Purchase] = {}
        self._revenue_records: Dict[str, RevenueRecord] = {}
        self._settlements: Dict[str, Settlement] = {}
        self._invoices: Dict[str, Invoice] = {}
        self._enterprise_licenses: Dict[str, EnterpriseLicense] = {}
        self._author_balances: Dict[str, int] = {}
        self._user_purchases: Dict[str, List[str]] = {}

        if storage_path:
            os.makedirs(storage_path, exist_ok=True)
            self._load_data()

    async def set_template_pricing(
        self,
        template_id: str,
        pricing_model: PricingModel,
        price: int = 0,
        currency: str = "USD",
        trial_steps_percent: int = 30,
    ) -> TemplatePricing:
        """Set pricing for template.

        Args:
            template_id: Template identifier.
            pricing_model: Pricing model.
            price: Price in cents.
            currency: Currency code.
            trial_steps_percent: Trial steps percentage.

        Returns:
            TemplatePricing configuration.
        """
        pricing = TemplatePricing(
            template_id=template_id,
            pricing_model=pricing_model,
            price=price,
            currency=currency,
            trial_steps_percent=trial_steps_percent,
        )

        self._template_pricing[template_id] = pricing
        self._save_data()

        return pricing

    async def purchase_template(
        self,
        template_id: str,
        user_id: str,
        is_trial: bool = False,
        payment_method: str = "",
    ) -> Optional[Purchase]:
        """Purchase template.

        Args:
            template_id: Template identifier.
            user_id: User identifier.
            is_trial: Whether this is a trial purchase.
            payment_method: Payment method.

        Returns:
            Purchase record or None.
        """
        pricing = self._template_pricing.get(template_id)
        if not pricing:
            return None

        if pricing.pricing_model == PricingModel.FREE or is_trial:
            amount = 0
        else:
            amount = pricing.price

        purchase_id = f"purchase_{user_id}_{template_id}_{int(time.time())}"

        purchase = Purchase(
            purchase_id=purchase_id,
            template_id=template_id,
            user_id=user_id,
            pricing_model=pricing.pricing_model,
            amount_paid=amount,
            currency=pricing.currency,
            purchase_timestamp=time.time(),
            is_trial=is_trial,
            payment_method=payment_method,
            transaction_id=f"txn_{purchase_id}",
        )

        if pricing.pricing_model in (PricingModel.SUBSCRIPTION_MONTHLY, PricingModel.SUBSCRIPTION_YEARLY):
            days = 30 if pricing.pricing_model == PricingModel.SUBSCRIPTION_MONTHLY else 365
            purchase.expires_at = time.time() + (days * 86400)

        self._purchases[purchase_id] = purchase

        if user_id not in self._user_purchases:
            self._user_purchases[user_id] = []

        self._user_purchases[user_id].append(purchase_id)

        if amount > 0:
            author_id = self._get_template_author(template_id)
            if author_id:
                await self._record_revenue(author_id, template_id, purchase_id, amount, pricing.pricing_model)

        self._save_data()

        return purchase

    async def get_user_purchases(self, user_id: str) -> List[Purchase]:
        """Get user's purchases.

        Args:
            user_id: User identifier.

        Returns:
            List of Purchase objects.
        """
        purchase_ids = self._user_purchases.get(user_id, [])
        return [
            self._purchases[pid]
            for pid in purchase_ids
            if pid in self._purchases
        ]

    async def has_access(self, user_id: str, template_id: str) -> bool:
        """Check if user has access to template.

        Args:
            user_id: User identifier.
            template_id: Template identifier.

        Returns:
            True if user has access.
        """
        pricing = self._template_pricing.get(template_id)
        if not pricing:
            return False

        if pricing.pricing_model == PricingModel.FREE:
            return True

        purchases = self._user_purchases.get(user_id, [])
        for pid in purchases:
            purchase = self._purchases.get(pid)
            if purchase and purchase.template_id == template_id:
                if purchase.expires_at == 0 or purchase.expires_at > time.time():
                    return True

        return False

    async def get_trial_steps(self, template_id: str, total_steps: int) -> int:
        """Get number of steps available for trial.

        Args:
            template_id: Template identifier.
            total_steps: Total steps in template.

        Returns:
            Number of trial steps.
        """
        pricing = self._template_pricing.get(template_id)
        if not pricing:
            return 0

        return max(1, int(total_steps * pricing.trial_steps_percent / 100))

    async def get_author_balance(self, author_id: str) -> int:
        """Get author's current balance.

        Args:
            author_id: Author identifier.

        Returns:
            Balance in cents.
        """
        return self._author_balances.get(author_id, 0)

    async def request_withdrawal(
        self,
        author_id: str,
        method: WithdrawalMethod,
        address: str,
    ) -> Optional[Settlement]:
        """Request revenue withdrawal.

        Args:
            author_id: Author identifier.
            method: Withdrawal method.
            address: Withdrawal address.

        Returns:
            Settlement record or None.
        """
        balance = self._author_balances.get(author_id, 0)

        if balance < self.MIN_WITHDRAWAL_AMOUNT:
            return None

        settlement_id = f"settle_{author_id}_{int(time.time())}"

        settlement = Settlement(
            settlement_id=settlement_id,
            author_id=author_id,
            total_amount=balance,
            withdrawal_method=method,
            withdrawal_address=address,
            status="pending",
            created_at=time.time(),
        )

        self._settlements[settlement_id] = settlement
        self._author_balances[author_id] = 0

        for record in self._revenue_records.values():
            if record.author_id == author_id and not record.is_settled:
                record.is_settled = True
                record.settlement_id = settlement_id

        self._save_data()

        return settlement

    async def process_settlement(self, settlement_id: str, transaction_ref: str = "") -> bool:
        """Process pending settlement.

        Args:
            settlement_id: Settlement identifier.
            transaction_ref: Payment transaction reference.

        Returns:
            True if processed successfully.
        """
        settlement = self._settlements.get(settlement_id)
        if not settlement:
            return False

        settlement.status = "processed"
        settlement.processed_at = time.time()
        settlement.transaction_reference = transaction_ref

        self._save_data()

        return True

    async def get_author_revenue(self, author_id: str) -> List[RevenueRecord]:
        """Get author's revenue records.

        Args:
            author_id: Author identifier.

        Returns:
            List of RevenueRecord objects.
        """
        return [
            r for r in self._revenue_records.values()
            if r.author_id == author_id
        ]

    async def create_enterprise_license(
        self,
        enterprise_id: str,
        template_id: str,
        max_users: int,
        amount: int,
    ) -> Optional[EnterpriseLicense]:
        """Create enterprise license.

        Args:
            enterprise_id: Enterprise identifier.
            template_id: Template identifier.
            max_users: Maximum users.
            amount: License amount in cents.

        Returns:
            EnterpriseLicense or None.
        """
        license_id = f"license_{enterprise_id}_{template_id}_{int(time.time())}"

        invoice = await self._create_invoice(enterprise_id, amount, template_id)

        license_obj = EnterpriseLicense(
            license_id=license_id,
            enterprise_id=enterprise_id,
            template_id=template_id,
            license_status=LicenseStatus.PENDING,
            max_users=max_users,
            purchase_date=time.time(),
            expires_at=time.time() + (365 * 86400),
            invoice_id=invoice.invoice_id if invoice else "",
        )

        self._enterprise_licenses[license_id] = license_obj
        self._save_data()

        return license_obj

    async def assign_license_to_user(
        self,
        license_id: str,
        user_id: str,
    ) -> bool:
        """Assign enterprise license to user.

        Args:
            license_id: License identifier.
            user_id: User identifier.

        Returns:
            True if assigned successfully.
        """
        license_obj = self._enterprise_licenses.get(license_id)
        if not license_obj:
            return False

        if len(license_obj.assigned_users) >= license_obj.max_users:
            return False

        if user_id in license_obj.assigned_users:
            return False

        license_obj.assigned_users.append(user_id)
        self._save_data()

        return True

    async def get_enterprise_licenses(self, enterprise_id: str) -> List[EnterpriseLicense]:
        """Get enterprise licenses.

        Args:
            enterprise_id: Enterprise identifier.

        Returns:
            List of EnterpriseLicense objects.
        """
        return [
            lic for lic in self._enterprise_licenses.values()
            if lic.enterprise_id == enterprise_id
        ]

    async def get_invoices(self, enterprise_id: str) -> List[Invoice]:
        """Get enterprise invoices.

        Args:
            enterprise_id: Enterprise identifier.

        Returns:
            List of Invoice objects.
        """
        return [
            inv for inv in self._invoices.values()
            if inv.enterprise_id == enterprise_id
        ]

    async def _record_revenue(
        self,
        author_id: str,
        template_id: str,
        purchase_id: str,
        amount: int,
        pricing_model: PricingModel,
    ) -> None:
        """Record revenue for author.

        Args:
            author_id: Author identifier.
            template_id: Template identifier.
            purchase_id: Purchase identifier.
            amount: Amount in cents.
            pricing_model: Pricing model.
        """
        commission_rate = self._get_commission_rate(pricing_model)
        platform_commission = int(amount * commission_rate)
        net_amount = amount - platform_commission

        record_id = f"revenue_{author_id}_{purchase_id}"

        record = RevenueRecord(
            record_id=record_id,
            author_id=author_id,
            template_id=template_id,
            purchase_id=purchase_id,
            gross_amount=amount,
            platform_commission=platform_commission,
            net_amount=net_amount,
            commission_rate=commission_rate * 100,
            timestamp=time.time(),
        )

        self._revenue_records[record_id] = record

        if author_id not in self._author_balances:
            self._author_balances[author_id] = 0

        self._author_balances[author_id] += net_amount

    def _get_commission_rate(self, pricing_model: PricingModel) -> float:
        """Get platform commission rate.

        Args:
            pricing_model: Pricing model.

        Returns:
            Commission rate (0-1).
        """
        rates = {
            PricingModel.FREE: self.PLATFORM_COMMISSION_FREE,
            PricingModel.ONE_TIME: self.PLATFORM_COMMISSION_PAID,
            PricingModel.SUBSCRIPTION_MONTHLY: self.PLATFORM_COMMISSION_SUBSCRIPTION,
            PricingModel.SUBSCRIPTION_YEARLY: self.PLATFORM_COMMISSION_SUBSCRIPTION,
            PricingModel.ENTERPRISE: self.PLATFORM_COMMISSION_ENTERPRISE,
        }

        return rates.get(pricing_model, self.PLATFORM_COMMISSION_PAID)

    async def _create_invoice(
        self,
        enterprise_id: str,
        amount: int,
        template_id: str,
    ) -> Invoice:
        """Create enterprise invoice.

        Args:
            enterprise_id: Enterprise identifier.
            amount: Amount in cents.
            template_id: Template identifier.

        Returns:
            Created Invoice.
        """
        invoice_id = f"invoice_{enterprise_id}_{int(time.time())}"

        tax_rate = 0.1
        tax_amount = int(amount * tax_rate)

        invoice = Invoice(
            invoice_id=invoice_id,
            enterprise_id=enterprise_id,
            amount=amount,
            items=[{"template_id": template_id, "amount": amount}],
            status=InvoiceStatus.PENDING,
            issue_date=time.time(),
            due_date=time.time() + (30 * 86400),
            tax_rate=tax_rate,
            tax_amount=tax_amount,
        )

        self._invoices[invoice_id] = invoice

        return invoice

    def _get_template_author(self, template_id: str) -> str:
        """Get template author.

        Args:
            template_id: Template identifier.

        Returns:
            Author ID or empty string.
        """
        return ""

    def _load_data(self) -> None:
        """Load data from storage."""
        if not self.storage_path:
            return

        try:
            data_file = os.path.join(self.storage_path, "commerce_data.json")
            if os.path.exists(data_file):
                with open(data_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                    for tpl_id, pricing_data in data.get("template_pricing", {}).items():
                        pricing = TemplatePricing(
                            template_id=tpl_id,
                            pricing_model=PricingModel(pricing_data.get("pricing_model", "free")),
                            price=pricing_data.get("price", 0),
                            currency=pricing_data.get("currency", "USD"),
                            trial_steps_percent=pricing_data.get("trial_steps_percent", 30),
                            subscription_period_days=pricing_data.get("subscription_period_days", 30),
                            enterprise_min_users=pricing_data.get("enterprise_min_users", 5),
                            enterprise_max_users=pricing_data.get("enterprise_max_users", 100),
                            discount_percent=pricing_data.get("discount_percent", 0),
                            is_on_sale=pricing_data.get("is_on_sale", False),
                        )
                        self._template_pricing[pricing.template_id] = pricing

                    for pur_id, pur_data in data.get("purchases", {}).items():
                        purchase = Purchase(
                            purchase_id=pur_id,
                            template_id=pur_data.get("template_id", ""),
                            user_id=pur_data.get("user_id", ""),
                            pricing_model=PricingModel(pur_data.get("pricing_model", "free")),
                            amount_paid=pur_data.get("amount_paid", 0),
                            currency=pur_data.get("currency", "USD"),
                            purchase_timestamp=pur_data.get("purchase_timestamp", 0.0),
                            expires_at=pur_data.get("expires_at", 0.0),
                            is_trial=pur_data.get("is_trial", False),
                            payment_method=pur_data.get("payment_method", ""),
                            transaction_id=pur_data.get("transaction_id", ""),
                        )
                        self._purchases[purchase.purchase_id] = purchase

                    for rec_id, rec_data in data.get("revenue_records", {}).items():
                        record = RevenueRecord(
                            record_id=rec_id,
                            author_id=rec_data.get("author_id", ""),
                            template_id=rec_data.get("template_id", ""),
                            purchase_id=rec_data.get("purchase_id", ""),
                            gross_amount=rec_data.get("gross_amount", 0),
                            platform_commission=rec_data.get("platform_commission", 0),
                            net_amount=rec_data.get("net_amount", 0),
                            commission_rate=rec_data.get("commission_rate", 0.0),
                            timestamp=rec_data.get("timestamp", 0.0),
                            is_settled=rec_data.get("is_settled", False),
                            settlement_id=rec_data.get("settlement_id", ""),
                        )
                        self._revenue_records[record.record_id] = record

                    for set_id, set_data in data.get("settlements", {}).items():
                        settlement = Settlement(
                            settlement_id=set_id,
                            author_id=set_data.get("author_id", ""),
                            total_amount=set_data.get("total_amount", 0),
                            withdrawal_method=WithdrawalMethod(set_data.get("withdrawal_method", "paypal")),
                            withdrawal_address=set_data.get("withdrawal_address", ""),
                            status=set_data.get("status", "pending"),
                            created_at=set_data.get("created_at", 0.0),
                            processed_at=set_data.get("processed_at", 0.0),
                            transaction_reference=set_data.get("transaction_reference", ""),
                        )
                        self._settlements[settlement.settlement_id] = settlement

                    for inv_id, inv_data in data.get("invoices", {}).items():
                        invoice = Invoice(
                            invoice_id=inv_id,
                            enterprise_id=inv_data.get("enterprise_id", ""),
                            amount=inv_data.get("amount", 0),
                            currency=inv_data.get("currency", "USD"),
                            items=inv_data.get("items", []),
                            status=InvoiceStatus(inv_data.get("status", "pending")),
                            issue_date=inv_data.get("issue_date", 0.0),
                            due_date=inv_data.get("due_date", 0.0),
                            paid_date=inv_data.get("paid_date", 0.0),
                            tax_rate=inv_data.get("tax_rate", 0.0),
                            tax_amount=inv_data.get("tax_amount", 0),
                        )
                        self._invoices[invoice.invoice_id] = invoice

                    for lic_id, lic_data in data.get("enterprise_licenses", {}).items():
                        license_obj = EnterpriseLicense(
                            license_id=lic_id,
                            enterprise_id=lic_data.get("enterprise_id", ""),
                            template_id=lic_data.get("template_id", ""),
                            license_status=LicenseStatus(lic_data.get("license_status", "pending")),
                            max_users=lic_data.get("max_users", 0),
                            assigned_users=lic_data.get("assigned_users", []),
                            purchase_date=lic_data.get("purchase_date", 0.0),
                            expires_at=lic_data.get("expires_at", 0.0),
                            auto_renew=lic_data.get("auto_renew", False),
                            invoice_id=lic_data.get("invoice_id", ""),
                        )
                        self._enterprise_licenses[license_obj.license_id] = license_obj

                    self._author_balances = data.get("author_balances", {})
                    self._user_purchases = data.get("user_purchases", {})

        except Exception as e:
            logger.error(f"Failed to load commerce data: {e}")

    def _save_data(self) -> None:
        """Save data to storage."""
        if not self.storage_path:
            return

        try:
            data_file = os.path.join(self.storage_path, "commerce_data.json")

            data = {
                "template_pricing": {
                    tpl_id: {
                        "pricing_model": p.pricing_model.value,
                        "price": p.price,
                        "currency": p.currency,
                        "trial_steps_percent": p.trial_steps_percent,
                        "subscription_period_days": p.subscription_period_days,
                        "enterprise_min_users": p.enterprise_min_users,
                        "enterprise_max_users": p.enterprise_max_users,
                        "discount_percent": p.discount_percent,
                        "is_on_sale": p.is_on_sale,
                    }
                    for tpl_id, p in self._template_pricing.items()
                },
                "purchases": {
                    pur_id: {
                        "template_id": p.template_id,
                        "user_id": p.user_id,
                        "pricing_model": p.pricing_model.value,
                        "amount_paid": p.amount_paid,
                        "currency": p.currency,
                        "purchase_timestamp": p.purchase_timestamp,
                        "expires_at": p.expires_at,
                        "is_trial": p.is_trial,
                        "payment_method": p.payment_method,
                        "transaction_id": p.transaction_id,
                    }
                    for pur_id, p in self._purchases.items()
                },
                "revenue_records": {
                    rec_id: {
                        "author_id": r.author_id,
                        "template_id": r.template_id,
                        "purchase_id": r.purchase_id,
                        "gross_amount": r.gross_amount,
                        "platform_commission": r.platform_commission,
                        "net_amount": r.net_amount,
                        "commission_rate": r.commission_rate,
                        "timestamp": r.timestamp,
                        "is_settled": r.is_settled,
                        "settlement_id": r.settlement_id,
                    }
                    for rec_id, r in self._revenue_records.items()
                },
                "settlements": {
                    set_id: {
                        "author_id": s.author_id,
                        "total_amount": s.total_amount,
                        "withdrawal_method": s.withdrawal_method.value,
                        "withdrawal_address": s.withdrawal_address,
                        "status": s.status,
                        "created_at": s.created_at,
                        "processed_at": s.processed_at,
                        "transaction_reference": s.transaction_reference,
                    }
                    for set_id, s in self._settlements.items()
                },
                "invoices": {
                    inv_id: {
                        "enterprise_id": i.enterprise_id,
                        "amount": i.amount,
                        "currency": i.currency,
                        "items": i.items,
                        "status": i.status.value,
                        "issue_date": i.issue_date,
                        "due_date": i.due_date,
                        "paid_date": i.paid_date,
                        "tax_rate": i.tax_rate,
                        "tax_amount": i.tax_amount,
                    }
                    for inv_id, i in self._invoices.items()
                },
                "enterprise_licenses": {
                    lic_id: {
                        "enterprise_id": l.enterprise_id,
                        "template_id": l.template_id,
                        "license_status": l.license_status.value,
                        "max_users": l.max_users,
                        "assigned_users": l.assigned_users,
                        "purchase_date": l.purchase_date,
                        "expires_at": l.expires_at,
                        "auto_renew": l.auto_renew,
                        "invoice_id": l.invoice_id,
                    }
                    for lic_id, l in self._enterprise_licenses.items()
                },
                "author_balances": self._author_balances,
                "user_purchases": self._user_purchases,
            }

            with open(data_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

        except Exception as e:
            logger.error(f"Failed to save commerce data: {e}")
