import { Elysia, t } from "elysia";
import { verifyToken, JWTPayload } from "../lib/jwt-service";
import { logAdminActivity, logSecurityEvent } from "../services/user-activity-service";
import { createUser, authenticateUser } from "../services/auth-service";
import { prisma } from "../lib/prisma";

export const adminRoutes = new Elysia({ prefix: "/admin" })
  
  // Middleware pentru verificare rol admin
  .derive(async ({ request, set }) => {
    const auth = request.headers.get("authorization");
    
    if (!auth || !auth.startsWith("Bearer ")) {
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";
      
      await logSecurityEvent('unauthorized_access', {
        endpoint: '/admin',
        reason: 'Missing or invalid authorization header'
      }, undefined, ipAddress, userAgent);
      
      set.status = 401;
      throw new Error("Unauthorized");
    }

    const token = auth.slice(7);
    const payload: JWTPayload = await verifyToken(token, "nextjs_client");
    
    if (payload.role !== "admin") {
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";
      
      await logSecurityEvent('unauthorized_access', {
        endpoint: '/admin',
        reason: 'Insufficient permissions - not admin',
        attempted_role: payload.role
      }, payload.email, ipAddress, userAgent);
      
      set.status = 403;
      throw new Error("Forbidden");
    }
    
    return { payload };
  })

  // Creare utilizator
  .post("/users", async ({ body, set, request, payload }) => {
    try {
      const { email, username, password, role } = body as any;
      
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";

      // Verificăm dacă email-ul există deja
      const existingUser = await prisma.users.findUnique({
        where: { email }
      });

      if (existingUser) {
        await logAdminActivity(payload.email, 'create_user', {
          success: false,
          reason: 'Email already exists',
          email,
          username,
          role
        }, ipAddress, userAgent);
        
        set.status = 409;
        return { error: "Email deja existent" };
      }

      const user = await createUser({ email, username, password, role });

      await logAdminActivity(payload.email, 'create_user', {
        success: true,
        created_user_id: user.id,
        email,
        username,
        role
      }, ipAddress, userAgent);

      set.status = 201;
      return { 
        message: "Utilizator creat cu succes",
        user: {
          id: user.id,
          email: user.email,
          username: user.username,
          role: user.role
        }
      };
    } catch (error) {
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";
      
      await logAdminActivity(payload.email, 'create_user', {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      }, ipAddress, userAgent);
      
      set.status = 500;
      return { error: "Eroare la crearea utilizatorului" };
    }
  }, {
    body: t.Object({
      email: t.String(),
      username: t.String(),
      password: t.String(),
      role: t.Union([t.Literal('pacient'), t.Literal('medic'), t.Literal('admin')])
    })
  })

  // Vizualizare toți utilizatorii
  .get("/users", async ({ request, payload }) => {
    try {
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";

      // Get both classic users and OAuth users
      const [classicUsers, oauthUsers] = await Promise.all([
        prisma.users.findMany({
          select: {
            id: true,
            email: true,
            username: true,
            role: true,
            created_at: true,
            updated_at: true,
            programari: {
              select: {
                id: true,
                serviciu: true,
                data_programare: true
              }
            }
          },
          orderBy: { created_at: 'desc' }
        }),
        prisma.oauth_users.findMany({
          select: {
            id: true,
            email: true,
            username: true,
            role: true,
            created_at: true,
            updated_at: true
          },
          orderBy: { created_at: 'desc' }
        })
      ]);

      // Combine and mark user type
      const allUsers = [
        ...classicUsers.map(user => ({ ...user, userType: 'classic' })),
        ...oauthUsers.map(user => ({ ...user, userType: 'oauth' }))
      ];
      
      await logAdminActivity(payload.email, 'view_users', {
        users_count: allUsers.length,
        classic_users: classicUsers.length,
        oauth_users: oauthUsers.length
      }, ipAddress, userAgent);

      return { users: allUsers };
    } catch (error) {
      console.error("Error fetching users:", error);
      return { error: "Eroare la încărcarea utilizatorilor" };
    }
  })

  // Actualizare utilizator
  .put("/users/:id", async ({ params, body, set, request, payload }) => {
    try {
      const { id } = params;
      const { email, username, role } = body as any;
      
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";

      const existingUser = await prisma.users.findUnique({
        where: { id }
      });

      if (!existingUser) {
        await logAdminActivity(payload.email, 'update_user', {
          success: false,
          reason: 'User not found',
          user_id: id
        }, ipAddress, userAgent);
        
        set.status = 404;
        return { error: "Utilizatorul nu a fost găsit" };
      }

      // Verificăm dacă noul email e unic
      if (email !== existingUser.email) {
        const emailExists = await prisma.users.findUnique({
          where: { email }
        });

        if (emailExists) {
          await logAdminActivity(payload.email, 'update_user', {
            success: false,
            reason: 'Email already exists',
            user_id: id,
            new_email: email
          }, ipAddress, userAgent);
          
          set.status = 409;
          return { error: "Email deja existent" };
        }
      }

      const updatedUser = await prisma.users.update({
        where: { id },
        data: {
          email,
          username,
          role,
          updated_at: new Date()
        }
      });

      await logAdminActivity(payload.email, 'update_user', {
        success: true,
        user_id: id,
        old_data: {
          email: existingUser.email,
          username: existingUser.username,
          role: existingUser.role
        },
        new_data: { email, username, role }
      }, ipAddress, userAgent);

      return { 
        message: "Utilizator actualizat cu succes",
        user: updatedUser 
      };
    } catch (error) {
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";
      
      await logAdminActivity(payload.email, 'update_user', {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      }, ipAddress, userAgent);
      
      set.status = 500;
      return { error: "Eroare la actualizarea utilizatorului" };
    }
  })

  // Ștergere utilizator
  .delete("/users/:id", async ({ params, set, request, payload }) => {
    try {
      const { id } = params;
      
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";

      // Check if user exists in either table
      const [classicUser, oauthUser] = await Promise.all([
        prisma.users.findUnique({ where: { id } }),
        prisma.oauth_users.findUnique({ where: { id } })
      ]);

      if (!classicUser && !oauthUser) {
        await logAdminActivity(payload.email, 'delete_user', {
          success: false,
          reason: 'User not found',
          user_id: id
        }, ipAddress, userAgent);
        
        set.status = 404;
        return { error: "Utilizatorul nu a fost găsit" };
      }

      // Don't allow deleting other admins
      const userToDelete = classicUser || oauthUser;
      if (userToDelete && userToDelete.role === 'admin' && userToDelete.id !== payload.sub) {
        await logAdminActivity(payload.email, 'delete_user', {
          success: false,
          reason: 'Cannot delete other admin users',
          user_id: id,
          target_role: 'admin'
        }, ipAddress, userAgent);
        
        set.status = 403;
        return { error: "Nu poți șterge alți utilizatori admin" };
      }

      // Delete from appropriate table
      if (classicUser) {
        await prisma.users.delete({ where: { id } });
      } else {
        await prisma.oauth_users.delete({ where: { id } });
      }

      await logAdminActivity(payload.email, 'delete_user', {
        success: true,
        deleted_user_id: id,
        deleted_user_type: classicUser ? 'classic' : 'oauth',
        deleted_data: {
          email: userToDelete?.email || 'unknown',
          username: userToDelete?.username || 'unknown',
          role: userToDelete?.role || 'unknown'
        }
      }, ipAddress, userAgent);

      return { message: "Utilizator șters cu succes" };
    } catch (error) {
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";
      
      await logAdminActivity(payload.email, 'delete_user', {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      }, ipAddress, userAgent);
      
      set.status = 500;
      return { error: "Eroare la ștergerea utilizatorului" };
    }
  })

  // Management permisiuni
  .post("/users/:id/permissions", async ({ params, body, set, request, payload }) => {
    try {
      const { id } = params;
      const { newRole } = body as any;
      
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";

      // Check if user exists in either table
      const [classicUser, oauthUser] = await Promise.all([
        prisma.users.findUnique({ where: { id } }),
        prisma.oauth_users.findUnique({ where: { id } })
      ]);

      if (!classicUser && !oauthUser) {
        await logAdminActivity(payload.email, 'manage_permissions', {
          success: false,
          reason: 'User not found',
          user_id: id,
          new_role: newRole
        }, ipAddress, userAgent);
        
        set.status = 404;
        return { error: "Utilizatorul nu a fost găsit" };
      }

      const existingUser = classicUser || oauthUser;
      
      // Update in appropriate table
      let updatedUser;
      if (classicUser) {
        updatedUser = await prisma.users.update({
          where: { id },
          data: {
            role: newRole,
            updated_at: new Date()
          }
        });
      } else {
        updatedUser = await prisma.oauth_users.update({
          where: { id },
          data: {
            role: newRole,
            updated_at: new Date()
          }
        });
      }

      await logAdminActivity(payload.email, 'manage_permissions', {
        success: true,
        user_id: id,
        email: existingUser!.email,
        old_role: existingUser!.role,
        new_role: newRole,
        user_type: classicUser ? 'classic' : 'oauth'
      }, ipAddress, userAgent);

      return { 
        message: "Permisiuni actualizate cu succes",
        user: updatedUser 
      };
    } catch (error) {
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";
      
      await logAdminActivity(payload.email, 'manage_permissions', {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      }, ipAddress, userAgent);
      
      set.status = 500;
      return { error: "Eroare la actualizarea permisiunilor" };
    }
  }, {
    body: t.Object({
      newRole: t.Union([t.Literal('pacient'), t.Literal('medic'), t.Literal('admin')])
    })
  })

  // Vizualizare log-uri de activitate
  .get("/activity-logs", async ({ request, query, payload }) => {
    try {
      const { user_id, action, resource, limit = 50, offset = 0 } = query as any;
      
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";

      const whereClause: any = {};
      if (user_id) whereClause.user_id = user_id;
      if (action) whereClause.action = action;
      if (resource) whereClause.resource = resource;

      const logs = await prisma.user_logs.findMany({
        where: whereClause,
        orderBy: { created_at: 'desc' },
        take: parseInt(limit),
        skip: parseInt(offset)
      });

      const total = await prisma.user_logs.count({ where: whereClause });

      await logAdminActivity(payload.email, 'view_activity_logs', {
        filters: { user_id, action, resource },
        results_count: logs.length,
        total_count: total
      }, ipAddress, userAgent);

      return { 
        logs,
        pagination: {
          total,
          limit: parseInt(limit),
          offset: parseInt(offset),
          has_more: offset + logs.length < total
        }
      };
    } catch (error) {
      console.error("Error fetching activity logs:", error);
      return { error: "Eroare la încărcarea log-urilor de activitate" };
    }
  })

  // Statistics endpoint
  .get("/stats", async ({ request, payload }) => {
    try {
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";

      // Get various statistics
      const [
        totalUsers,
        totalPatients,
        totalDoctors,
        totalAdmins,
        totalAppointments,
        todayAppointments,
        recentLogs
      ] = await Promise.all([
        prisma.users.count(),
        prisma.users.count({ where: { role: 'pacient' } }),
        prisma.users.count({ where: { role: 'medic' } }),
        prisma.users.count({ where: { role: 'admin' } }),
        prisma.programari.count(),
        prisma.programari.count({
          where: {
            data_programare: {
              gte: new Date(new Date().setHours(0, 0, 0, 0)),
              lt: new Date(new Date().setHours(23, 59, 59, 999))
            }
          }
        }),
        prisma.user_logs.findMany({
          orderBy: { created_at: 'desc' },
          take: 10
        })
      ]);

      const stats = {
        users: {
          total: totalUsers,
          patients: totalPatients,
          doctors: totalDoctors,
          admins: totalAdmins
        },
        appointments: {
          total: totalAppointments,
          today: todayAppointments
        },
        recentActivity: recentLogs.map(log => ({
          id: log.id,
          action: log.action,
          resource: log.resource,
          user_id: log.user_id,
          created_at: log.created_at,
          details: log.details
        }))
      };

      await logAdminActivity(payload.email, 'view_stats', {
        stats_generated: true
      }, ipAddress, userAgent);

      return { stats };
    } catch (error) {
      console.error("Error fetching stats:", error);
      return { error: "Eroare la încărcarea statisticilor" };
    }
  })

  // Get password reset tokens
  .get("/password-reset-tokens", async ({ payload, request }) => {
    try {
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";

      console.log("🔍 Fetching password reset tokens...");
      console.log("🔍 Prisma client available:", !!prisma);
      console.log("🔍 Table exists check...");

      // Fetch all password reset tokens without the actual token field
      const tokens = await prisma.password_reset_tokens.findMany({
        select: {
          id: true,
          email: true,
          expires_at: true,
          created_at: true,
          used: true,
          user_type: true
          // Note: 'token' field is excluded for security
        },
        orderBy: {
          created_at: 'desc'
        }
      });

      console.log("🔍 Successfully fetched tokens:", tokens.length);

      await logAdminActivity(payload.email, 'view_stats', {
        action: 'view_password_reset_tokens',
        tokens_count: tokens.length
      }, ipAddress, userAgent);

      return { tokens };
    } catch (error) {
      console.error("🔍 Error fetching password reset tokens:", error);
      console.error("🔍 Error details:", error instanceof Error ? error.message : 'Unknown error');
      console.error("🔍 Error stack:", error instanceof Error ? error.stack : 'No stack');
      
      return { error: "Eroare la încărcarea token-urilor de resetare" };
    }
  })

  // GET - Fetch all program lucru
  .get("/program-lucru", async ({ payload, request }) => {
    try {
      console.log("🔍 Auth-server: GET /program-lucru called");
      
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";

      console.log("🔍 Fetching program lucru...");

      // Fetch all program lucru
      const programs = await prisma.program_lucru.findMany({
        orderBy: {
          created_at: 'desc'
        }
      });

      console.log("🔍 Successfully fetched program lucru:", programs.length);
      console.log("🔍 Programs data:", programs);

      await logAdminActivity(payload.email, 'view_stats', {
        action: 'view_program_lucru',
        programs_count: programs.length
      }, ipAddress, userAgent);

      return { programLucru: programs };
    } catch (error) {
      console.error("🔍 Error fetching program lucru:", error);
      console.error("🔍 Error details:", error instanceof Error ? error.message : 'Unknown error');
      console.error("🔍 Error stack:", error instanceof Error ? error.stack : 'No stack');
      
      return { error: "Eroare la încărcarea programelor de lucru" };
    }
  })

  // POST - Create new program lucru
  .post("/program-lucru", async ({ body, payload, request }) => {
    console.log("🔍 Auth-server: POST /program-lucru received - START");
    console.log("🔍 Auth-server: Request body:", body);
    console.log("🔍 Auth-server: Payload:", payload);
    
    try {
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";

      console.log("🔍 Creating program lucru with data:", body);

      const { medic_info_id, ora_inceput, ora_sfarsit, activ } = body as any;

      // Validate required fields
      if (!medic_info_id || !ora_inceput || !ora_sfarsit) {
        return { error: "Toate câmpurile obligatorii trebuie completate" };
      }

      // Check if medic_info_id exists
      const medicExists = await prisma.medic_info.findUnique({
        where: { id: parseInt(medic_info_id) }
      });

      if (!medicExists) {
        console.log("🔍 Medic info not found for ID:", medic_info_id);
        return { error: `Medic cu ID ${medic_info_id} nu există` };
      }

      console.log("🔍 Medic info found:", medicExists);

      // Convert time strings to DateTime objects
      const oraInceputDateTime = new Date();
      const [startHour, startMinute] = ora_inceput.split(':');
      oraInceputDateTime.setHours(parseInt(startHour), parseInt(startMinute), 0, 0);
      
      const oraSfarsitDateTime = new Date();
      const [endHour, endMinute] = ora_sfarsit.split(':');
      oraSfarsitDateTime.setHours(parseInt(endHour), parseInt(endMinute), 0, 0);

      // Create program lucru
      const newProgram = await prisma.program_lucru.create({
        data: {
          medic_info_id: parseInt(medic_info_id),
          ora_inceput: oraInceputDateTime,
          ora_sfarsit: oraSfarsitDateTime,
          activ: activ !== undefined ? activ : true
        }
      });

      console.log("🔍 Successfully created program lucru:", newProgram.id);

      await logAdminActivity(payload.email, 'view_stats', {
        action: 'create_program_lucru',
        program_id: newProgram.id,
        medic_info_id: newProgram.medic_info_id
      }, ipAddress, userAgent);

      return { programLucru: newProgram };
    } catch (error) {
      console.log("🔍 Auth-server: CATCH BLOCK - ERROR OCCURRED");
      console.error("🔍 Error creating program lucru:", error);
      console.error("🔍 Error details:", error instanceof Error ? error.message : 'Unknown error');
      console.error("🔍 Error stack:", error instanceof Error ? error.stack : 'No stack');
      console.error("🔍 Request body received:", body);
      console.error("🔍 Payload:", payload);
      
      return { error: "Eroare la crearea programului de lucru" };
    }
  })

  // PUT - Update program lucru
  .put("/program-lucru/:id", async ({ params, body, payload, request }) => {
    try {
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";

      console.log("🔍 Updating program lucru ID:", params.id, "with data:", body);

      const { ora_inceput, ora_sfarsit, activ } = body as any;
      const id = parseInt(params.id);

      // Check if program exists
      const existingProgram = await prisma.program_lucru.findUnique({
        where: { id }
      });

      if (!existingProgram) {
        return { error: "Programul de lucru nu a fost găsit" };
      }

      // Update program lucru
      const updatedProgram = await prisma.program_lucru.update({
        where: { id },
        data: {
          ...(ora_inceput && { ora_inceput }),
          ...(ora_sfarsit && { ora_sfarsit }),
          ...(activ !== undefined && { activ })
        }
      });

      console.log("🔍 Successfully updated program lucru:", updatedProgram.id);

      await logAdminActivity(payload.email, 'view_stats', {
        action: 'update_program_lucru',
        program_id: updatedProgram.id,
        medic_info_id: updatedProgram.medic_info_id
      }, ipAddress, userAgent);

      return { programLucru: updatedProgram };
    } catch (error) {
      console.error("🔍 Error updating program lucru:", error);
      console.error("🔍 Error details:", error instanceof Error ? error.message : 'Unknown error');
      
      return { error: "Eroare la actualizarea programului de lucru" };
    }
  })

  // DELETE - Delete program lucru
  .delete("/program-lucru/:id", async ({ params, payload, request }) => {
    try {
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";

      console.log("🔍 Deleting program lucru ID:", params.id);
      const id = parseInt(params.id);

      // Check if program exists
      const existingProgram = await prisma.program_lucru.findUnique({
        where: { id }
      });

      if (!existingProgram) {
        return { error: "Programul de lucru nu a fost găsit" };
      }

      // Delete program lucru
      await prisma.program_lucru.delete({
        where: { id }
      });

      console.log("🔍 Successfully deleted program lucru:", id);

      await logAdminActivity(payload.email, 'view_stats', {
        action: 'delete_program_lucru',
        program_id: id,
        medic_info_id: existingProgram.medic_info_id
      }, ipAddress, userAgent);

      return { success: true };
    } catch (error) {
      console.error("🔍 Error deleting program lucru:", error);
      console.error("🔍 Error details:", error instanceof Error ? error.message : 'Unknown error');
      
      return { error: "Eroare la ștergerea programului de lucru" };
    }
  });
