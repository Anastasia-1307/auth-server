import { prisma } from "../lib/prisma";

export interface LogActivityData {
  user_id?: string;
  action: string;
  resource?: string;
  ip_address?: string;
  user_agent?: string;
  details?: any;
}

export async function getRealUserId(email: string): Promise<string | null> {
  try {
    // În auth server, căutăm doar în users (utilizatori clasici)
    const user = await prisma.users.findUnique({
      where: { email },
      select: { id: true }
    });
    
    return user?.id || null;
  } catch (error) {
    console.error("❌ Failed to get user ID:", error);
    return null;
  }
}

export async function logUserActivity(data: LogActivityData) {
  try {
    await prisma.user_logs.create({
      data: {
        user_id: data.user_id,
        action: data.action,
        resource: data.resource,
        ip_address: data.ip_address,
        user_agent: data.user_agent,
        details: data.details ? JSON.stringify(data.details) : undefined
      }
    });
    
    console.log(`🔍 Activity logged: ${data.action} for user ${data.user_id || 'anonymous'}`);
  } catch (error) {
    console.error("❌ Failed to log user activity:", error);
    // Nu aruncăm eroarea pentru a nu afecta fluxul principal
  }
}

export async function logAuthActivity(
  action: 'login' | 'register' | 'logout',
  email: string,
  ipAddress?: string,
  userAgent?: string
) {
  // Obține ID-ul real al utilizatorului
  const realUserId = await getRealUserId(email);
  
  return logUserActivity({
    user_id: realUserId || undefined,
    action,
    resource: 'auth',
    ip_address: ipAddress,
    user_agent: userAgent,
    details: { email }
  });
}

export async function logSecurityEvent(
  action: 'brute_force_attempt' | 'unauthorized_access' | 'suspicious_activity' | 'rate_limit_exceeded',
  details: any,
  email?: string,
  ipAddress?: string,
  userAgent?: string
) {
  // Logăm evenimente de securitate fără user_id (atacator nu e autentificat)
  return logUserActivity({
    user_id: undefined,
    action,
    resource: 'security',
    ip_address: ipAddress,
    user_agent: userAgent,
    details: { email, ...details }
  });
}

export async function logMedicalActivity(
  email: string,
  action: 'create_appointment' | 'update_appointment' | 'delete_appointment' | 'view_appointments' | 'view_patients',
  details: any,
  ipAddress?: string,
  userAgent?: string
) {
  const realUserId = await getRealUserId(email);
  
  return logUserActivity({
    user_id: realUserId || undefined,
    action,
    resource: 'medical',
    ip_address: ipAddress,
    user_agent: userAgent,
    details: { ...details, email }
  });
}

export async function logAdminActivity(
  email: string,
  action: 'create_user' | 'update_user' | 'delete_user' | 'view_users' | 'manage_permissions' | 'view_activity_logs' | 'view_stats',
  details: any,
  ipAddress?: string,
  userAgent?: string
) {
  const realUserId = await getRealUserId(email);
  
  return logUserActivity({
    user_id: realUserId || undefined,
    action,
    resource: 'admin',
    ip_address: ipAddress,
    user_agent: userAgent,
    details: { ...details, email }
  });
}

export async function logResourceAccess(
  email: string,
  resource: string,
  action: string = 'access',
  ipAddress?: string,
  userAgent?: string,
  details?: any
) {
  // Obține ID-ul real al utilizatorului
  const realUserId = await getRealUserId(email);
  
  return logUserActivity({
    user_id: realUserId || undefined,
    action,
    resource,
    ip_address: ipAddress,
    user_agent: userAgent,
    details: { ...details, email }
  });
}

export async function logFailedAuthActivity(
  action: 'login_failed' | 'register_failed',
  email: string,
  reason: string,
  ipAddress?: string,
  userAgent?: string
) {
  // Logăm activitatea fără user_id (nu avem utilizator valid)
  return logUserActivity({
    user_id: undefined,
    action,
    resource: 'auth',
    ip_address: ipAddress,
    user_agent: userAgent,
    details: { email, reason }
  });
}

export async function logFailedOAuthActivity(
  action: 'login_failed' | 'register_failed',
  email: string,
  reason: string,
  ipAddress?: string,
  userAgent?: string
) {
  // Logăm activitatea OAuth fără user_id (nu avem utilizator valid)
  return logUserActivity({
    user_id: undefined,
    action,
    resource: 'oauth',
    ip_address: ipAddress,
    user_agent: userAgent,
    details: { email, reason }
  });
}
