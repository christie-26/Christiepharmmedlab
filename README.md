 - CHRISTIESPECIAL'S PHARM & MED LAB
-- SUPABASE POSTGRESQL DATABASE SCHEMA
-- Run in a FRESH Supabase project.
-- Authentication is handled by Supabase Auth.
-- Never store plaintext passwords.

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

-- 1. ENUM TYPES

DO $$ BEGIN
  CREATE TYPE public.account_role AS ENUM (
    'customer','ceo','pharmacist','accountant',
    'inventory_manager','lab_scientist','dispatcher',
    'delivery_rider','cleaner'
  );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
  CREATE TYPE public.account_status AS ENUM (
    'pending','active','suspended','rejected'
  );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
  CREATE TYPE public.order_status AS ENUM (
    'placed','awaiting_pharmacy_review','pharmacy_rejected',
    'verified','awaiting_payment','paid','processing',
    'ready_for_dispatch','dispatched','out_for_delivery',
    'delivered','cancelled','refunded'
  );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
  CREATE TYPE public.prescription_status AS ENUM (
    'not_required','submitted','under_review','approved','rejected'
  );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
  CREATE TYPE public.payment_status AS ENUM (
    'pending','successful','failed','refunded'
  );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
  CREATE TYPE public.delivery_status AS ENUM (
    'unassigned','assigned','picked_up','in_transit',
    'attempted','delivered','failed','returned'
  );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- 2. GENERAL FUNCTIONS

CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

-- 3. USER PROFILES

CREATE TABLE IF NOT EXISTS public.profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  full_name TEXT NOT NULL DEFAULT '',
  email CITEXT,
  phone TEXT,
  role public.account_role NOT NULL DEFAULT 'customer',
  department TEXT,
  status public.account_status NOT NULL DEFAULT 'active',
  approved_by UUID REFERENCES public.profiles(id),
  approved_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT department_required_for_staff
    CHECK (role = 'customer' OR role = 'ceo' OR department IS NOT NULL)
);

-- 4. ROLE AND ACCESS FUNCTIONS

CREATE OR REPLACE FUNCTION public.is_ceo()
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.profiles p
    WHERE p.id = auth.uid()
      AND p.role = 'ceo'
      AND p.status = 'active'
  );
$$;

CREATE OR REPLACE FUNCTION public.has_staff_access()
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.profiles p
    WHERE p.id = auth.uid()
      AND p.role <> 'customer'
      AND p.status = 'active'
  );
$$;

CREATE OR REPLACE FUNCTION public.has_role(
  roles public.account_role[]
)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.profiles p
    WHERE p.id = auth.uid()
      AND p.role = ANY(roles)
      AND p.status = 'active'
  );
$$;

-- 5. PROTECT STAFF PRIVILEGES

CREATE OR REPLACE FUNCTION public.protect_profile_privileges()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF auth.uid() = OLD.id AND NOT public.is_ceo() THEN
    IF NEW.role IS DISTINCT FROM OLD.role
       OR NEW.status IS DISTINCT FROM OLD.status
       OR NEW.department IS DISTINCT FROM OLD.department
       OR NEW.approved_by IS DISTINCT FROM OLD.approved_by
       OR NEW.approved_at IS DISTINCT FROM OLD.approved_at
    THEN
      RAISE EXCEPTION
        'Only the CEO may change staff role, department or account approval';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_protect_profile_privileges
ON public.profiles;

CREATE TRIGGER trg_protect_profile_privileges
BEFORE UPDATE ON public.profiles
FOR EACH ROW
EXECUTE PROCEDURE public.protect_profile_privileges();

-- 6. STAFF ACCESS REQUESTS

CREATE TABLE IF NOT EXISTS public.staff_access_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL UNIQUE REFERENCES auth.users(id) ON DELETE CASCADE,
  requested_role public.account_role NOT NULL
    CHECK (requested_role <> 'ceo' AND requested_role <> 'customer'),
  requested_department TEXT NOT NULL,
  job_title TEXT,
  message TEXT,
  status public.account_status NOT NULL DEFAULT 'pending',
  reviewed_by UUID REFERENCES public.profiles(id),
  reviewed_at TIMESTAMPTZ,
  review_note TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 7. AUTOMATIC CUSTOMER PROFILE AFTER SIGNUP

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO public.profiles (
    id, full_name, email, phone, role, status
  )
  VALUES (
    NEW.id,
    COALESCE(NEW.raw_user_meta_data->>'full_name',''),
    NEW.email,
    NEW.raw_user_meta_data->>'phone',
    'customer',
    'active'
  )
  ON CONFLICT (id) DO NOTHING;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created_profile
ON auth.users;

CREATE TRIGGER on_auth_user_created_profile
AFTER INSERT ON auth.users
FOR EACH ROW
EXECUTE PROCEDURE public.handle_new_user();

-- 8. CUSTOMER ADDRESSES

CREATE TABLE IF NOT EXISTS public.customer_addresses (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  customer_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  label TEXT,
  recipient_name TEXT NOT NULL,
  phone TEXT NOT NULL,
  address_line TEXT NOT NULL,
  city TEXT NOT NULL,
  state TEXT,
  country TEXT NOT NULL DEFAULT 'Nigeria',
  postal_code TEXT,
  delivery_instructions TEXT,
  is_default BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 9. PRODUCT CATEGORIES

CREATE TABLE IF NOT EXISTS public.product_categories (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL UNIQUE,
  description TEXT,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 10. PRODUCTS

CREATE TABLE IF NOT EXISTS public.products (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  category_id UUID REFERENCES public.product_categories(id)
    ON DELETE SET NULL,
  name TEXT NOT NULL,
  brand TEXT,
  sku TEXT UNIQUE,
  description TEXT,
  image_url TEXT,
  price NUMERIC(12,2) NOT NULL CHECK (price >= 0),
  currency CHAR(3) NOT NULL DEFAULT 'NGN',
  requires_prescription BOOLEAN NOT NULL DEFAULT FALSE,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_by UUID REFERENCES public.profiles(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 11. INVENTORY

CREATE TABLE IF NOT EXISTS public.inventory (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  product_id UUID NOT NULL UNIQUE
    REFERENCES public.products(id) ON DELETE CASCADE,
  quantity_on_hand INTEGER NOT NULL DEFAULT 0
    CHECK (quantity_on_hand >= 0),
  reorder_level INTEGER NOT NULL DEFAULT 5
    CHECK (reorder_level >= 0),
  updated_by UUID REFERENCES public.profiles(id),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 12. INVENTORY BATCHES

CREATE TABLE IF NOT EXISTS public.inventory_batches (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  product_id UUID NOT NULL
    REFERENCES public.products(id) ON DELETE CASCADE,
  batch_number TEXT NOT NULL,
  quantity_received INTEGER NOT NULL CHECK (quantity_received >= 0),
  quantity_remaining INTEGER NOT NULL CHECK (quantity_remaining >= 0),
  expiry_date DATE,
  received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  received_by UUID REFERENCES public.profiles(id),
  UNIQUE(product_id, batch_number)
);

-- 13. STOCK MOVEMENTS

CREATE TABLE IF NOT EXISTS public.stock_movements (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  product_id UUID NOT NULL REFERENCES public.products(id),
  batch_id UUID REFERENCES public.inventory_batches(id),
  movement_type TEXT NOT NULL CHECK (
    movement_type IN (
      'received','dispensed','adjustment',
      'return','damaged','expired'
    )
  ),
  quantity INTEGER NOT NULL CHECK (quantity > 0),
  reference TEXT,
  notes TEXT,
  performed_by UUID REFERENCES public.profiles(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 14. CUSTOMER ORDERS

CREATE TABLE IF NOT EXISTS public.orders (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  order_number TEXT NOT NULL UNIQUE DEFAULT (
    'CS-' || UPPER(
      SUBSTR(REPLACE(gen_random_uuid()::TEXT,'-',''),1,10)
    )
  ),
  customer_id UUID NOT NULL REFERENCES public.profiles(id),
  address_id UUID REFERENCES public.customer_addresses(id),
  status public.order_status NOT NULL DEFAULT 'placed',
  prescription_status public.prescription_status
    NOT NULL DEFAULT 'not_required',
  subtotal NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK (subtotal >= 0),
  delivery_fee NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK (delivery_fee >= 0),
  discount NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK (discount >= 0),
  total NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK (total >= 0),
  currency CHAR(3) NOT NULL DEFAULT 'NGN',
  customer_note TEXT,
  pharmacy_note TEXT,
  verified_by UUID REFERENCES public.profiles(id),
  verified_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 15. ORDER ITEMS

CREATE TABLE IF NOT EXISTS public.order_items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  order_id UUID NOT NULL REFERENCES public.orders(id) ON DELETE CASCADE,
  product_id UUID REFERENCES public.products(id) ON DELETE SET NULL,
  product_name TEXT NOT NULL,
  quantity INTEGER NOT NULL CHECK (quantity > 0),
  unit_price NUMERIC(12,2) NOT NULL CHECK (unit_price >= 0),
  line_total NUMERIC(12,2) NOT NULL CHECK (line_total >= 0)
);

-- 16. PRESCRIPTIONS

CREATE TABLE IF NOT EXISTS public.prescriptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  order_id UUID REFERENCES public.orders(id) ON DELETE SET NULL,
  customer_id UUID NOT NULL REFERENCES public.profiles(id),
  file_path TEXT NOT NULL,
  status public.prescription_status NOT NULL DEFAULT 'submitted',
  reviewed_by UUID REFERENCES public.profiles(id),
  reviewed_at TIMESTAMPTZ,
  review_notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 17. PHARMACY REVIEWS

CREATE TABLE IF NOT EXISTS public.pharmacy_reviews (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  order_id UUID NOT NULL REFERENCES public.orders(id) ON DELETE CASCADE,
  pharmacist_id UUID NOT NULL REFERENCES public.profiles(id),
  decision TEXT NOT NULL CHECK (
    decision IN ('approved','rejected','more_information_required')
  ),
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 18. PAYMENTS

CREATE TABLE IF NOT EXISTS public.payments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  order_id UUID NOT NULL REFERENCES public.orders(id) ON DELETE CASCADE,
  customer_id UUID NOT NULL REFERENCES public.profiles(id),
  provider TEXT NOT NULL DEFAULT 'paystack',
  provider_reference TEXT UNIQUE,
  amount NUMERIC(12,2) NOT NULL CHECK (amount >= 0),
  currency CHAR(3) NOT NULL DEFAULT 'NGN',
  status public.payment_status NOT NULL DEFAULT 'pending',
  verified_at TIMESTAMPTZ,
  provider_payload JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 19. DISPATCH ASSIGNMENTS

CREATE TABLE IF NOT EXISTS public.dispatch_assignments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  order_id UUID NOT NULL REFERENCES public.orders(id) ON DELETE CASCADE,
  dispatcher_id UUID REFERENCES public.profiles(id),
  rider_id UUID REFERENCES public.profiles(id),
  status public.delivery_status NOT NULL DEFAULT 'unassigned',
  assigned_at TIMESTAMPTZ,
  picked_up_at TIMESTAMPTZ,
  delivered_at TIMESTAMPTZ,
  delivery_fee NUMERIC(12,2) DEFAULT 0,
  recipient_name TEXT,
  recipient_phone TEXT,
  delivery_notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 20. DELIVERY EVENTS

CREATE TABLE IF NOT EXISTS public.delivery_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  assignment_id UUID NOT NULL
    REFERENCES public.dispatch_assignments(id) ON DELETE CASCADE,
  status public.delivery_status NOT NULL,
  location_text TEXT,
  note TEXT,
  proof_file_path TEXT,
  recorded_by UUID REFERENCES public.profiles(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 21. ORDER STATUS HISTORY

CREATE TABLE IF NOT EXISTS public.order_status_history (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  order_id UUID NOT NULL REFERENCES public.orders(id) ON DELETE CASCADE,
  old_status public.order_status,
  new_status public.order_status NOT NULL,
  note TEXT,
  changed_by UUID REFERENCES public.profiles(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 22. LABORATORY TEST CATALOGUE

CREATE TABLE IF NOT EXISTS public.lab_test_catalog (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL UNIQUE,
  description TEXT,
  price NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK (price >= 0),
  sample_type TEXT,
  turnaround_hours INTEGER,
  is_active BOOLEAN NOT NULL DEFAULT TRUE
);

-- 23. LABORATORY REQUESTS

CREATE TABLE IF NOT EXISTS public.lab_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  request_number TEXT NOT NULL UNIQUE DEFAULT (
    'LAB-' || UPPER(
      SUBSTR(REPLACE(gen_random_uuid()::TEXT,'-',''),1,10)
    )
  ),
  customer_id UUID NOT NULL REFERENCES public.profiles(id),
  requested_by UUID REFERENCES public.profiles(id),
  status TEXT NOT NULL DEFAULT 'requested'
    CHECK (
      status IN (
        'requested','scheduled','sample_collected',
        'processing','completed','cancelled'
      )
    ),
  clinical_notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 24. LABORATORY REQUEST ITEMS

CREATE TABLE IF NOT EXISTS public.lab_request_items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id UUID NOT NULL
    REFERENCES public.lab_requests(id) ON DELETE CASCADE,
  test_id UUID REFERENCES public.lab_test_catalog(id),
  test_name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (
      status IN ('pending','processing','completed','cancelled')
    )
);

-- 25. LABORATORY RESULTS

CREATE TABLE IF NOT EXISTS public.lab_results (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  request_item_id UUID NOT NULL UNIQUE
    REFERENCES public.lab_request_items(id) ON DELETE CASCADE,
  result_text TEXT,
  result_file_path TEXT,
  scientist_id UUID REFERENCES public.profiles(id),
  reviewed_by UUID REFERENCES public.profiles(id),
  released_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 26. APPOINTMENTS

CREATE TABLE IF NOT EXISTS public.appointments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  customer_id UUID NOT NULL REFERENCES public.profiles(id),
  service_type TEXT NOT NULL,
  scheduled_at TIMESTAMPTZ NOT NULL,
  status TEXT NOT NULL DEFAULT 'requested'
    CHECK (
      status IN ('requested','confirmed','completed','cancelled')
    ),
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 27. HEALTH ENQUIRIES

CREATE TABLE IF NOT EXISTS public.health_enquiries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  customer_id UUID NOT NULL REFERENCES public.profiles(id),
  subject TEXT NOT NULL,
  message TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'new'
    CHECK (status IN ('new','assigned','responded','closed')),
  assigned_to UUID REFERENCES public.profiles(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 28. CLEANING TASKS

CREATE TABLE IF NOT EXISTS public.cleaning_tasks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title TEXT NOT NULL,
  location TEXT,
  instructions TEXT,
  assigned_to UUID REFERENCES public.profiles(id),
  due_at TIMESTAMPTZ,
  status TEXT NOT NULL DEFAULT 'open'
    CHECK (
      status IN ('open','in_progress','completed','verified')
    ),
  completed_at TIMESTAMPTZ,
  verified_by UUID REFERENCES public.profiles(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 29. INVOICES

CREATE TABLE IF NOT EXISTS public.invoices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  order_id UUID NOT NULL UNIQUE
    REFERENCES public.orders(id) ON DELETE CASCADE,
  invoice_number TEXT NOT NULL UNIQUE DEFAULT (
    'INV-' || UPPER(
      SUBSTR(REPLACE(gen_random_uuid()::TEXT,'-',''),1,10)
    )
  ),
  issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  due_at TIMESTAMPTZ,
  amount NUMERIC(12,2) NOT NULL CHECK (amount >= 0),
  status TEXT NOT NULL DEFAULT 'unpaid'
    CHECK (status IN ('unpaid','paid','void'))
);

-- 30. EXPENSES

CREATE TABLE IF NOT EXISTS public.expenses (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  description TEXT NOT NULL,
  category TEXT,
  amount NUMERIC(12,2) NOT NULL CHECK (amount >= 0),
  expense_date DATE NOT NULL DEFAULT CURRENT_DATE,
  receipt_path TEXT,
  recorded_by UUID REFERENCES public.profiles(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 31. NOTIFICATIONS

CREATE TABLE IF NOT EXISTS public.notifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  recipient_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE,
  channel TEXT NOT NULL
    CHECK (channel IN ('in_app','email','whatsapp','sms')),
  event_type TEXT NOT NULL,
  destination TEXT,
  message TEXT NOT NULL,
  payload JSONB NOT NULL DEFAULT '{}'::JSONB,
  status TEXT NOT NULL DEFAULT 'queued'
    CHECK (status IN ('queued','sent','failed','read')),
  provider_message_id TEXT,
  sent_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 32. ACTIVITY LOGS

CREATE TABLE IF NOT EXISTS public.activity_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_id UUID REFERENCES public.profiles(id),
  action TEXT NOT NULL,
  entity_type TEXT,
  entity_id UUID,
  details JSONB NOT NULL DEFAULT '{}'::JSONB,
  ip_address INET,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 33. AUTOMATIC ORDER STATUS HISTORY

CREATE OR REPLACE FUNCTION public.log_order_status_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    INSERT INTO public.order_status_history (
      order_id, old_status, new_status, changed_by
    )
    VALUES (
      NEW.id, NULL, NEW.status, auth.uid()
    );

  ELSIF NEW.status IS DISTINCT FROM OLD.status THEN
    INSERT INTO public.order_status_history (
      order_id, old_status, new_status, changed_by
    )
    VALUES (
      NEW.id, OLD.status, NEW.status, auth.uid()
    );
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_order_status_history
ON public.orders;

CREATE TRIGGER trg_order_status_history
AFTER INSERT OR UPDATE OF status ON public.orders
FOR EACH ROW
EXECUTE PROCEDURE public.log_order_status_change();

-- 34. AUTOMATIC UPDATED_AT TRIGGERS

DO $$
DECLARE
  t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'profiles','products','inventory',
    'orders','dispatch_assignments','lab_requests'
  ]
  LOOP
    EXECUTE FORMAT(
      'DROP TRIGGER IF EXISTS trg_%I_updated_at ON public.%I',
      t,t
    );

    EXECUTE FORMAT(
      'CREATE TRIGGER trg_%I_updated_at
       BEFORE UPDATE ON public.%I
       FOR EACH ROW
       EXECUTE PROCEDURE public.set_updated_at()',
      t,t
    );
  END LOOP;
END;
$$;

-- 35. ENABLE ROW LEVEL SECURITY

DO $$
DECLARE
  t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'profiles','staff_access_requests','customer_addresses',
    'product_categories','products','inventory',
    'inventory_batches','stock_movements','orders',
    'order_items','prescriptions','pharmacy_reviews',
    'payments','dispatch_assignments','delivery_events',
    'order_status_history','lab_test_catalog','lab_requests',
    'lab_request_items','lab_results','appointments',
    'health_enquiries','cleaning_tasks','invoices',
    'expenses','notifications','activity_logs'
  ]
  LOOP
    EXECUTE FORMAT(
      'ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',
      t
    );
  END LOOP;
END;
$$;

-- 36. PROFILE POLICIES

CREATE POLICY "profile read self or CEO"
ON public.profiles
FOR SELECT
USING (id = auth.uid() OR public.is_ceo());

CREATE POLICY "profile update self contact"
ON public.profiles
FOR UPDATE
USING (id = auth.uid())
WITH CHECK (id = auth.uid());

CREATE POLICY "CEO manages profiles"
ON public.profiles
FOR ALL
USING (public.is_ceo())
WITH CHECK (public.is_ceo());

-- 37. STAFF ACCESS POLICIES

CREATE POLICY "staff request own access"
ON public.staff_access_requests
FOR INSERT
WITH CHECK (user_id = auth.uid());

CREATE POLICY "staff view own request"
ON public.staff_access_requests
FOR SELECT
USING (user_id = auth.uid() OR public.is_ceo());

CREATE POLICY "CEO reviews access"
ON public.staff_access_requests
FOR ALL
USING (public.is_ceo())
WITH CHECK (public.is_ceo());

-- 38. PRODUCT POLICIES

CREATE POLICY "active products public read"
ON public.product_categories
FOR SELECT
USING (is_active OR public.has_staff_access());

CREATE POLICY "active product public read"
ON public.products
FOR SELECT
USING (is_active OR public.has_staff_access());

CREATE POLICY "CEO and inventory manage products"
ON public.products
FOR ALL
USING (
  public.has_role(
    ARRAY['ceo','inventory_manager']::public.account_role[]
  )
)
WITH CHECK (
  public.has_role(
    ARRAY['ceo','inventory_manager']::public.account_role[]
  )
);

CREATE POLICY "CEO manages categories"
ON public.product_categories
FOR ALL
USING (public.is_ceo())
WITH CHECK (public.is_ceo());

-- 39. INVENTORY POLICIES

CREATE POLICY "staff inventory read"
ON public.inventory
FOR SELECT
USING (
  public.has_role(
    ARRAY[
      'ceo','inventory_manager','accountant','pharmacist'
    ]::public.account_role[]
  )
);

CREATE POLICY "inventory team manages inventory"
ON public.inventory
FOR ALL
USING (
  public.has_role(
    ARRAY['ceo','inventory_manager']::public.account_role[]
  )
)
WITH CHECK (
  public.has_role(
    ARRAY['ceo','inventory_manager']::public.account_role[]
  )
);

CREATE POLICY "inventory team batches"
ON public.inventory_batches
FOR ALL
USING (
  public.has_role(
    ARRAY['ceo','inventory_manager']::public.account_role[]
  )
)
WITH CHECK (
  public.has_role(
    ARRAY['ceo','inventory_manager']::public.account_role[]
  )
);

CREATE POLICY "staff stock movements read"
ON public.stock_movements
FOR SELECT
USING (public.has_staff_access());

CREATE POLICY "inventory records movements"
ON public.stock_movements
FOR INSERT
WITH CHECK (
  public.has_role(
    ARRAY[
      'ceo','inventory_manager','pharmacist'
    ]::public.account_role[]
  )
);

-- 40. CUSTOMER ADDRESS POLICIES

CREATE POLICY "customer addresses own"
ON public.customer_addresses
FOR ALL
USING (
  customer_id = auth.uid() OR public.is_ceo()
)
WITH CHECK (
  customer_id = auth.uid() OR public.is_ceo()
);

-- 41. ORDER POLICIES

CREATE POLICY "orders customer or authorized staff read"
ON public.orders
FOR SELECT
USING (
  customer_id = auth.uid()
  OR public.has_role(
    ARRAY[
      'ceo','pharmacist','accountant',
      'inventory_manager','dispatcher','delivery_rider'
    ]::public.account_role[]
  )
);

CREATE POLICY "customer creates own order"
ON public.orders
FOR INSERT
WITH CHECK (customer_id = auth.uid());

CREATE POLICY "authorized staff updates orders"
ON public.orders
FOR UPDATE
USING (
  public.has_role(
    ARRAY[
      'ceo','pharmacist','accountant',
      'inventory_manager','dispatcher'
    ]::public.account_role[]
  )
)
WITH CHECK (
  public.has_role(
    ARRAY[
      'ceo','pharmacist','accountant',
      'inventory_manager','dispatcher'
    ]::public.account_role[]
  )
);

-- 42. ORDER ITEM POLICIES

CREATE POLICY "order items visible to order owner or staff"
ON public.order_items
FOR SELECT
USING (
  EXISTS (
    SELECT 1
    FROM public.orders o
    WHERE o.id = order_id
      AND (
        o.customer_id = auth.uid()
        OR public.has_staff_access()
      )
  )
);

CREATE POLICY "customer adds own order items"
ON public.order_items
FOR INSERT
WITH CHECK (
  EXISTS (
    SELECT 1
    FROM public.orders o
    WHERE o.id = order_id
      AND o.customer_id = auth.uid()
  )
);

CREATE POLICY "staff updates order items"
ON public.order_items
FOR ALL
USING (
  public.has_role(
    ARRAY[
      'ceo','pharmacist','inventory_manager'
    ]::public.account_role[]
  )
)
WITH CHECK (
  public.has_role(
    ARRAY[
      'ceo','pharmacist','inventory_manager'
    ]::public.account_role[]
  )
);

-- 43. PRESCRIPTION POLICIES

CREATE POLICY "prescription owner and pharmacy read"
ON public.prescriptions
FOR SELECT
USING (
  customer_id = auth.uid()
  OR public.has_role(
    ARRAY['ceo','pharmacist']::public.account_role[]
  )
);

CREATE POLICY "customer submits prescription"
ON public.prescriptions
FOR INSERT
WITH CHECK (customer_id = auth.uid());

CREATE POLICY "pharmacy reviews prescription"
ON public.prescriptions
FOR UPDATE
USING (
  public.has_role(
    ARRAY['ceo','pharmacist']::public.account_role[]
  )
)
WITH CHECK (
  public.has_role(
    ARRAY['ceo','pharmacist']::public.account_role[]
  )
);

CREATE POLICY "pharmacy reviews visible"
ON public.pharmacy_reviews
FOR SELECT
USING (
  public.has_role(
    ARRAY['ceo','pharmacist']::public.account_role[]
  )
);

CREATE POLICY "pharmacy creates review"
ON public.pharmacy_reviews
FOR INSERT
WITH CHECK (
  public.has_role(
    ARRAY['ceo','pharmacist']::public.account_role[]
  )
);

-- 44. PAYMENT POLICIES

CREATE POLICY "payments customer or finance read"
ON public.payments
FOR SELECT
USING (
  customer_id = auth.uid()
  OR public.has_role(
    ARRAY['ceo','accountant']::public.account_role[]
  )
);

CREATE POLICY "customer creates pending payment"
ON public.payments
FOR INSERT
WITH CHECK (
  customer_id = auth.uid()
  AND status = 'pending'
);

CREATE POLICY "CEO finance manages payments"
ON public.payments
FOR ALL
USING (
  public.has_role(
    ARRAY['ceo','accountant']::public.account_role[]
  )
)
WITH CHECK (
  public.has_role(
    ARRAY['ceo','accountant']::public.account_role[]
  )
);

-- 45. DISPATCH POLICIES

CREATE POLICY "dispatch staff and customer view assignment"
ON public.dispatch_assignments
FOR SELECT
USING (
  public.has_role(
    ARRAY['ceo','dispatcher','delivery_rider']::public.account_role[]
  )
  OR EXISTS (
    SELECT 1
    FROM public.orders o
    WHERE o.id = order_id
      AND o.customer_id = auth.uid()
  )
);

CREATE POLICY "dispatch staff manage assignment"
ON public.dispatch_assignments
FOR ALL
USING (
  public.has_role(
    ARRAY['ceo','dispatcher']::public.account_role[]
  )
)
WITH CHECK (
  public.has_role(
    ARRAY['ceo','dispatcher']::public.account_role[]
  )
);

CREATE POLICY "rider updates own assignment"
ON public.dispatch_assignments
FOR UPDATE
USING (
  rider_id = auth.uid()
  AND public.has_role(
    ARRAY['delivery_rider']::public.account_role[]
  )
)
WITH CHECK (
  rider_id = auth.uid()
);

CREATE POLICY "delivery events visible"
ON public.delivery_events
FOR SELECT
USING (
  public.has_staff_access()
  OR EXISTS (
    SELECT 1
    FROM public.dispatch_assignments d
    JOIN public.orders o ON o.id = d.order_id
    WHERE d.id = assignment_id
      AND o.customer_id = auth.uid()
  )
);

CREATE POLICY "delivery team records events"
ON public.delivery_events
FOR INSERT
WITH CHECK (
  public.has_role(
    ARRAY[
      'ceo','dispatcher','delivery_rider'
    ]::public.account_role[]
  )
);

CREATE POLICY "order history customer or staff read"
ON public.order_status_history
FOR SELECT
USING (
  EXISTS (
    SELECT 1
    FROM public.orders o
    WHERE o.id = order_id
      AND (
        o.customer_id = auth.uid()
        OR public.has_staff_access()
      )
  )
);

-- 46. LABORATORY POLICIES

CREATE POLICY "lab catalogue public read"
ON public.lab_test_catalog
FOR SELECT
USING (is_active OR public.has_staff_access());

CREATE POLICY "CEO manages lab catalogue"
ON public.lab_test_catalog
FOR ALL
USING (public.is_ceo())
WITH CHECK (public.is_ceo());

CREATE POLICY "lab requests owner or lab team read"
ON public.lab_requests
FOR SELECT
USING (
  customer_id = auth.uid()
  OR public.has_role(
    ARRAY['ceo','lab_scientist']::public.account_role[]
  )
);

CREATE POLICY "customer creates lab request"
ON public.lab_requests
FOR INSERT
WITH CHECK (customer_id = auth.uid());

CREATE POLICY "lab team updates requests"
ON public.lab_requests
FOR UPDATE
USING (
  public.has_role(
    ARRAY['ceo','lab_scientist']::public.account_role[]
  )
)
WITH CHECK (
  public.has_role(
    ARRAY['ceo','lab_scientist']::public.account_role[]
  )
);

CREATE POLICY "lab items owner or staff read"
ON public.lab_request_items
FOR SELECT
USING (
  EXISTS (
    SELECT 1
    FROM public.lab_requests r
    WHERE r.id = request_id
      AND (
        r.customer_id = auth.uid()
        OR public.has_role(
          ARRAY['ceo','lab_scientist']::public.account_role[]
        )
      )
  )
);

CREATE POLICY "lab team manages test items"
ON public.lab_request_items
FOR ALL
USING (
  public.has_role(
    ARRAY['ceo','lab_scientist']::public.account_role[]
  )
)
WITH CHECK (
  public.has_role(
    ARRAY['ceo','lab_scientist']::public.account_role[]
  )
);

CREATE POLICY "results customer or lab team read"
ON public.lab_results
FOR SELECT
USING (
  EXISTS (
    SELECT 1
    FROM public.lab_request_items i
    JOIN public.lab_requests r ON r.id = i.request_id
    WHERE i.id = request_item_id
      AND (
        (r.customer_id = auth.uid() AND released_at IS NOT NULL)
        OR public.has_role(
          ARRAY['ceo','lab_scientist']::public.account_role[]
        )
      )
  )
);

CREATE POLICY "lab team manages results"
ON public.lab_results
FOR ALL
USING (
  public.has_role(
    ARRAY['ceo','lab_scientist']::public.account_role[]
  )
)
WITH CHECK (
  public.has_role(
    ARRAY['ceo','lab_scientist']::public.account_role[]
  )
);

-- 47. APPOINTMENT POLICIES

CREATE POLICY "appointments own or CEO"
ON public.appointments
FOR ALL
USING (
  customer_id = auth.uid() OR public.is_ceo()
)
WITH CHECK (
  customer_id = auth.uid() OR public.is_ceo()
);

-- 48. HEALTH ENQUIRY POLICIES

CREATE POLICY "health enquiries own or assigned staff"
ON public.health_enquiries
FOR SELECT
USING (
  customer_id = auth.uid()
  OR assigned_to = auth.uid()
  OR public.is_ceo()
  OR public.has_role(
    ARRAY['pharmacist','lab_scientist']::public.account_role[]
  )
);

CREATE POLICY "customer submits enquiry"
ON public.health_enquiries
FOR INSERT
WITH CHECK (customer_id = auth.uid());

CREATE POLICY "assigned clinical staff handles enquiry"
ON public.health_enquiries
FOR UPDATE
USING (
  public.has_role(
    ARRAY['ceo','pharmacist','lab_scientist']::public.account_role[]
  )
)
WITH CHECK (
  public.has_role(
    ARRAY['ceo','pharmacist','lab_scientist']::public.account_role[]
  )
);

-- 49. CLEANING TASK POLICIES

CREATE POLICY "cleaning team sees tasks"
ON public.cleaning_tasks
FOR SELECT
USING (
  assigned_to = auth.uid()
  OR public.has_role(
    ARRAY['ceo','cleaner']::public.account_role[]
  )
);

CREATE POLICY "CEO assigns cleaning tasks"
ON public.cleaning_tasks
FOR INSERT
WITH CHECK (public.is_ceo());

CREATE POLICY "cleaner updates assigned task"
ON public.cleaning_tasks
FOR UPDATE
USING (
  (
    assigned_to = auth.uid()
    AND public.has_role(
      ARRAY['cleaner']::public.account_role[]
    )
  )
  OR public.is_ceo()
)
WITH CHECK (
  (
    assigned_to = auth.uid()
    AND public.has_role(
      ARRAY['cleaner']::public.account_role[]
    )
  )
  OR public.is_ceo()
);

-- 50. FINANCE POLICIES

CREATE POLICY "invoice customer or finance read"
ON public.invoices
FOR SELECT
USING (
  EXISTS (
    SELECT 1
    FROM public.orders o
    WHERE o.id = order_id
      AND o.customer_id = auth.uid()
  )
  OR public.has_role(
    ARRAY['ceo','accountant']::public.account_role[]
  )
);

CREATE POLICY "finance manages invoices"
ON public.invoices
FOR ALL
USING (
  public.has_role(
    ARRAY['ceo','accountant']::public.account_role[]
  )
)
WITH CHECK (
  public.has_role(
    ARRAY['ceo','accountant']::public.account_role[]
  )
);

CREATE POLICY "finance manages expenses"
ON public.expenses
FOR ALL
USING (
  public.has_role(
    ARRAY['ceo','accountant']::public.account_role[]
  )
)
WITH CHECK (
  public.has_role(
    ARRAY['ceo','accountant']::public.account_role[]
  )
);

-- 51. NOTIFICATION POLICIES

CREATE POLICY "users read own notifications"
ON public.notifications
FOR SELECT
USING (
  recipient_id = auth.uid() OR public.is_ceo()
);

CREATE POLICY "CEO and backend queue notifications"
ON public.notifications
FOR ALL
USING (public.is_ceo())
WITH CHECK (public.is_ceo());

-- 52. ACTIVITY LOG POLICIES

CREATE POLICY "CEO reads audit log"
ON public.activity_logs
FOR SELECT
USING (public.is_ceo());

CREATE POLICY "authenticated user writes own audit event"
ON public.activity_logs
FOR INSERT
WITH CHECK (actor_id = auth.uid());

-- 53. DATABASE INDEXES

CREATE INDEX IF NOT EXISTS idx_orders_customer_created
ON public.orders(customer_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_orders_status
ON public.orders(status);

CREATE INDEX IF NOT EXISTS idx_order_items_order
ON public.order_items(order_id);

CREATE INDEX IF NOT EXISTS idx_prescriptions_status
ON public.prescriptions(status);

CREATE INDEX IF NOT EXISTS idx_payments_order
ON public.payments(order_id);

CREATE INDEX IF NOT EXISTS idx_dispatch_status
ON public.dispatch_assignments(status);

CREATE INDEX IF NOT EXISTS idx_delivery_events_assignment
ON public.delivery_events(assignment_id, created_at);

CREATE INDEX IF NOT EXISTS idx_notifications_status
ON public.notifications(status, created_at);

CREATE INDEX IF NOT EXISTS idx_lab_requests_customer
ON public.lab_requests(customer_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_staff_requests_status
ON public.staff_access_requests(status, created_at);

-- 54. INITIAL PRODUCT CATEGORIES

INSERT INTO public.product_categories(name, description)
VALUES
(
  'Prescription Medicines',
  'Medicines requiring pharmacist review and valid prescription where applicable'
),
(
  'Over-the-Counter Medicines',
  'Non-prescription medicines'
),
(
  'Wellness & Personal Care',
  'Health, hygiene and personal care products'
),
(
  'Medical Supplies',
  'Basic medical and diagnostic supplies'
),
(
  'Laboratory Services',
  'Medical laboratory tests and diagnostic services'
)
ON CONFLICT(name) DO NOTHING;

-- 55. CEO ACCOUNT SETUP
--
-- FIRST:
-- Create your CEO user through Supabase Dashboard:
-- Authentication > Users > Add User.
--
-- NEXT:
-- Copy the UUID of the CEO account you created.
--
-- THEN:
-- Replace the placeholder below with that UUID and run
-- the UPDATE statement separately.
--
-- Do not allow public registration to assign the CEO role.
--
-- UPDATE public.profiles
-- SET role = 'ceo',
--     status = 'active',
--     department = 'Executive',
--     approved_at = NOW()
-- WHERE id = 'PASTE-AUTH-USER-UUID-HERE';

-- 56. PRODUCTION SECURITY NOTES
--
-- 1. Keep SUPABASE_SERVICE_ROLE_KEY and payment-provider secrets
--    only in secure server-side functions or Edge Function secrets.
--
-- 2. Verify Paystack payment webhooks server-side before changing
--    payments.status to 'successful'.
--
-- 3. Use a WhatsApp Business Platform provider from an Edge Function
--    to send automatic notifications. Never expose API tokens in HTML.
--
-- 4. Create private Storage buckets for prescriptions, lab results
--    and delivery proof. Add appropriate Storage RLS policies.
--
-- 5. Add applicable pharmacy, laboratory, privacy, consent and
--    data-retention controls before production launch.
--
-- END OF DATABASE SCHEMA
