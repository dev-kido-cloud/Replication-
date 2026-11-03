/**
 * Tenant Row Level Security (RLS) & Isolation Policy Layer
 * Ensures that every query, request header, query parameter, and payload
 * is automatically scoped by the current authenticated user's tenant ID,
 * strictly preventing cross-tenant data access and leaks.
 */

export function enforceTenantIsolation(config, activeTenantId) {
    if (!config) return config;

    const url = String(config.url || '');
    const isAuthRoute = /\/api\/(?:v1\/auth|auth)(\/|$)/.test(url);
    const isPlatformRoute = /\/api\/v1\/admin\/tenants(\/|$)/.test(url);

    if (isAuthRoute || isPlatformRoute) {
        return config;
    }

    // Initialize headers if missing
    config.headers = config.headers || {};

    const tenantIdToEnforce = activeTenantId || (typeof window !== 'undefined' ? localStorage.getItem('pharma_tenant_id') : null);

    if (tenantIdToEnforce) {
        // Enforce X-Tenant-Id header
        config.headers['X-Tenant-Id'] = tenantIdToEnforce;
        config.headers['x-tenant-id'] = tenantIdToEnforce;

        // Enforce query parameter tenant scoping
        if (config.method?.toLowerCase() === 'get') {
            config.params = config.params || {};
            if (!config.params.tenantId) {
                config.params.tenantId = tenantIdToEnforce;
            } else if (String(config.params.tenantId) !== String(tenantIdToEnforce)) {
                console.error('[Tenant RLS Security Violation] Cross-tenant query attempt blocked!', {
                    attemptedTenant: config.params.tenantId,
                    authorizedTenant: tenantIdToEnforce,
                    url
                });
                throw new Error('Cross-tenant query access denied by RLS policy.');
            }
        }

        // Enforce request body tenant scoping for mutations (POST, PUT, PATCH)
        if (['post', 'put', 'patch'].includes(config.method?.toLowerCase()) && config.data && typeof config.data === 'object') {
            if (!config.data.tenantId) {
                config.data.tenantId = tenantIdToEnforce;
            } else if (String(config.data.tenantId) !== String(tenantIdToEnforce)) {
                console.error('[Tenant RLS Security Violation] Cross-tenant mutation attempt blocked!', {
                    attemptedTenant: config.data.tenantId,
                    authorizedTenant: tenantIdToEnforce,
                    url
                });
                throw new Error('Cross-tenant data mutation denied by RLS policy.');
            }
        }
    }

    return config;
}

export function validateTenantRecord(record, activeTenantId) {
    if (!record || !activeTenantId) return true;
    const recordTenantId = record.tenantId || record._tenantId;
    if (recordTenantId && String(recordTenantId) !== String(activeTenantId)) {
        console.error('[Tenant RLS Security Violation] Cross-tenant record leakage blocked!', {
            recordTenant: recordTenantId,
            authorizedTenant: activeTenantId
        });
        return false;
    }
    return true;
}
