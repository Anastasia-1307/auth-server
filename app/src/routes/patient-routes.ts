import { Elysia, t } from "elysia";
import { verifyToken, JWTPayload } from "../lib/jwt-service";
import { logResourceAccess, logSecurityEvent } from "../services/user-activity-service";
import { prisma } from "../lib/prisma";

export const patientRoutes = new Elysia({ prefix: "/patient" })
  
  // Middleware pentru verificare rol pacient
  .derive(async ({ request, set }) => {
    const auth = request.headers.get("authorization");
    
    if (!auth || !auth.startsWith("Bearer ")) {
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";
      
      await logSecurityEvent('unauthorized_access', {
        endpoint: '/patient',
        reason: 'Missing or invalid authorization header'
      }, undefined, ipAddress, userAgent);
      
      set.status = 401;
      throw new Error("Unauthorized");
    }

    const token = auth.slice(7);
    const payload: JWTPayload = await verifyToken(token, "nextjs_client");
    
    if (payload.role !== "pacient") {
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";
      
      await logSecurityEvent('unauthorized_access', {
        endpoint: '/patient',
        reason: 'Insufficient permissions - not patient',
        attempted_role: payload.role
      }, payload.email, ipAddress, userAgent);
      
      set.status = 403;
      throw new Error("Forbidden");
    }
    
    return { payload };
  })

  // Pacientul își poate vedea programările
  .get("/appointments", async ({ request, payload }) => {
    try {
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";

      // Obținem ID-ul real al pacientului
      const patient = await prisma.users.findUnique({
        where: { email: payload.email }
      });

      if (!patient) {
        await logResourceAccess(payload.email, 'patient_appointments', 'view_failed', ipAddress, userAgent, {
          reason: 'Patient not found'
        });
        
        return { error: "Pacientul nu a fost găsit" };
      }

      const appointments = await prisma.programari.findMany({
        where: { user_id: patient.id },
        orderBy: { data_programare: 'asc' }
      });

      await logResourceAccess(payload.email, 'patient_appointments', 'view', ipAddress, userAgent, {
        appointments_count: appointments.length
      });

      return { appointments };
    } catch (error) {
      console.error("Error fetching patient appointments:", error);
      return { error: "Eroare la încărcarea programărilor" };
    }
  })

  // Pacientul poate crea o programare nouă
  .post("/appointments", async ({ body, set, request, payload }) => {
    try {
      const { serviciu, data_programare, notes } = body as any;
      
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";

      // Obținem ID-ul real al pacientului
      const patient = await prisma.users.findUnique({
        where: { email: payload.email }
      });

      if (!patient) {
        await logResourceAccess(payload.email, 'patient_appointments', 'create_failed', ipAddress, userAgent, {
          reason: 'Patient not found',
          serviciu,
          data_programare
        });
        
        set.status = 404;
        return { error: "Pacientul nu a fost găsit" };
      }

      // Verificăm dacă nu există deja o programare la aceeași dată
      const existingAppointment = await prisma.programari.findFirst({
        where: {
          user_id: patient.id,
          data_programare: new Date(data_programare)
        }
      });

      if (existingAppointment) {
        await logResourceAccess(payload.email, 'patient_appointments', 'create_failed', ipAddress, userAgent, {
          reason: 'Appointment already exists at this time',
          serviciu,
          data_programare
        });
        
        set.status = 409;
        return { error: "Deja există o programare la această dată și oră" };
      }

      const appointment = await prisma.programari.create({
        data: {
          user_id: patient.id,
          serviciu,
          data_programare: new Date(data_programare),
          created_at: new Date(),
          updated_at: new Date()
        }
      });

      await logResourceAccess(payload.email, 'patient_appointments', 'create', ipAddress, userAgent, {
        success: true,
        appointment_id: appointment.id,
        serviciu,
        data_programare,
        notes
      });

      set.status = 201;
      return { 
        message: "Programare creată cu succes",
        appointment 
      };
    } catch (error) {
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";
      
      await logResourceAccess(payload.email, 'patient_appointments', 'create_failed', ipAddress, userAgent, {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      
      set.status = 500;
      return { error: "Eroare la crearea programării" };
    }
  }, {
    body: t.Object({
      serviciu: t.String(),
      data_programare: t.String(),
      notes: t.Optional(t.String())
    })
  })

  // Pacientul poate actualiza programarea sa (doar data și serviciul)
  .put("/appointments/:id", async ({ params, body, set, request, payload }) => {
    try {
      const { id } = params;
      const { serviciu, data_programare, notes } = body as any;
      
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";

      // Obținem ID-ul real al pacientului
      const patient = await prisma.users.findUnique({
        where: { email: payload.email }
      });

      if (!patient) {
        await logResourceAccess(payload.email, 'patient_appointments', 'update_failed', ipAddress, userAgent, {
          reason: 'Patient not found',
          appointment_id: id
        });
        
        set.status = 404;
        return { error: "Pacientul nu a fost găsit" };
      }

      // Verificăm dacă programarea aparține pacientului
      const existingAppointment = await prisma.programari.findFirst({
        where: { 
          id: parseInt(id),
          user_id: patient.id 
        }
      });

      if (!existingAppointment) {
        await logResourceAccess(payload.email, 'patient_appointments', 'update_failed', ipAddress, userAgent, {
          reason: 'Appointment not found or not owned by patient',
          appointment_id: id
        });
        
        set.status = 404;
        return { error: "Programarea nu a fost găsită sau nu aparține pacientului" };
      }

      // Verificăm dacă nu există altă programare la noua dată
      if (data_programare) {
        const conflictAppointment = await prisma.programari.findFirst({
          where: {
            user_id: patient.id,
            data_programare: new Date(data_programare),
            id: { not: parseInt(id) }
          }
        });

        if (conflictAppointment) {
          await logResourceAccess(payload.email, 'patient_appointments', 'update_failed', ipAddress, userAgent, {
            reason: 'Another appointment exists at this time',
            appointment_id: id,
            new_data_programare: data_programare
          });
          
          set.status = 409;
          return { error: "Deja există o altă programare la această dată și oră" };
        }
      }

      const updatedAppointment = await prisma.programari.update({
        where: { id: parseInt(id) },
        data: {
          ...(serviciu && { serviciu }),
          ...(data_programare && { data_programare: new Date(data_programare) }),
          updated_at: new Date()
        }
      });

      await logResourceAccess(payload.email, 'patient_appointments', 'update', ipAddress, userAgent, {
        success: true,
        appointment_id: id,
        old_data: {
          serviciu: existingAppointment.serviciu,
          data_programare: existingAppointment.data_programare
        },
        new_data: { serviciu, data_programare, notes }
      });

      return { 
        message: "Programare actualizată cu succes",
        appointment: updatedAppointment 
      };
    } catch (error) {
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";
      
      await logResourceAccess(payload.email, 'patient_appointments', 'update_failed', ipAddress, userAgent, {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      
      set.status = 500;
      return { error: "Eroare la actualizarea programării" };
    }
  })

  // Pacientul poate șterge programarea sa
  .delete("/appointments/:id", async ({ params, set, request, payload }) => {
    try {
      const { id } = params;
      
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";

      // Obținem ID-ul real al pacientului
      const patient = await prisma.users.findUnique({
        where: { email: payload.email }
      });

      if (!patient) {
        await logResourceAccess(payload.email, 'patient_appointments', 'delete_failed', ipAddress, userAgent, {
          reason: 'Patient not found',
          appointment_id: id
        });
        
        set.status = 404;
        return { error: "Pacientul nu a fost găsit" };
      }

      // Verificăm dacă programarea aparține pacientului
      const existingAppointment = await prisma.programari.findFirst({
        where: { 
          id: parseInt(id),
          user_id: patient.id 
        }
      });

      if (!existingAppointment) {
        await logResourceAccess(payload.email, 'patient_appointments', 'delete_failed', ipAddress, userAgent, {
          reason: 'Appointment not found or not owned by patient',
          appointment_id: id
        });
        
        set.status = 404;
        return { error: "Programarea nu a fost găsită sau nu aparține pacientului" };
      }

      await prisma.programari.delete({
        where: { id: parseInt(id) }
      });

      await logResourceAccess(payload.email, 'patient_appointments', 'delete', ipAddress, userAgent, {
        success: true,
        appointment_id: id,
        deleted_data: {
          serviciu: existingAppointment.serviciu,
          data_programare: existingAppointment.data_programare
        }
      });

      return { message: "Programare ștearsă cu succes" };
    } catch (error) {
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";
      
      await logResourceAccess(payload.email, 'patient_appointments', 'delete_failed', ipAddress, userAgent, {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      
      set.status = 500;
      return { error: "Eroare la ștergerea programării" };
    }
  })

  // Pacientul își poate vedea profilul
  .get("/profile", async ({ request, payload }) => {
    try {
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";

      const patient = await prisma.users.findUnique({
        where: { email: payload.email },
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
              data_programare: true,
              created_at: true
            },
            orderBy: { data_programare: 'desc' },
            take: 5
          }
        }
      });

      if (!patient) {
        return { error: "Pacientul nu a fost găsit" };
      }

      await logResourceAccess(payload.email, 'patient_profile', 'view', ipAddress, userAgent, {
        user_id: patient.id
      });

      return { patient };
    } catch (error) {
      console.error("Error fetching patient profile:", error);
      return { error: "Eroare la încărcarea profilului" };
    }
  })

  // Pacientul poate vedea medicii disponibili
  .get("/doctors", async ({ request, payload }) => {
    try {
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";

      const doctors = await prisma.users.findMany({
        where: { role: 'medic' },
        select: {
          id: true,
          email: true,
          username: true,
          created_at: true
        }
      });

      await logResourceAccess(payload.email, 'patient_doctors', 'view', ipAddress, userAgent, {
        doctors_count: doctors.length
      });

      return { doctors };
    } catch (error) {
      console.error("Error fetching doctors:", error);
      return { error: "Eroare la încărcarea medicilor" };
    }
  });
