import { Elysia, t } from "elysia";
import { verifyToken, JWTPayload } from "../lib/jwt-service";
import { logMedicalActivity, logSecurityEvent } from "../services/user-activity-service";
import { prisma } from "../lib/prisma";

export const medicalRoutes = new Elysia({ prefix: "/medical" })
  
  // Middleware pentru verificare rol medic
  .derive(async ({ request, set }) => {
    const auth = request.headers.get("authorization");
    
    if (!auth || !auth.startsWith("Bearer ")) {
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";
      
      await logSecurityEvent('unauthorized_access', {
        endpoint: '/medical',
        reason: 'Missing or invalid authorization header'
      }, undefined, ipAddress, userAgent);
      
      set.status = 401;
      throw new Error("Unauthorized");
    }

    const token = auth.slice(7);
    const payload: JWTPayload = await verifyToken(token, "nextjs_client");
    
    if (payload.role !== "medic" && payload.role !== "admin") {
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";
      
      await logSecurityEvent('unauthorized_access', {
        endpoint: '/medical',
        reason: 'Insufficient permissions - not medic or admin',
        attempted_role: payload.role
      }, payload.email, ipAddress, userAgent);
      
      set.status = 403;
      throw new Error("Forbidden");
    }
    
    return { payload };
  })

  // Creare programare
  .post("/appointments", async ({ body, set, request, payload }) => {
    try {
      const { patient_id, serviciu, data_programare, notes } = body as any;
      
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";

      // Verificăm dacă pacientul există
      const patient = await prisma.users.findUnique({
        where: { id: patient_id, role: 'pacient' }
      });

      if (!patient) {
        await logMedicalActivity(payload.email, 'create_appointment', {
          success: false,
          reason: 'Patient not found',
          patient_id
        }, ipAddress, userAgent);
        
        set.status = 404;
        return { error: "Pacientul nu a fost găsit" };
      }

      const appointment = await prisma.programari.create({
        data: {
          user_id: patient_id,
          serviciu,
          data_programare: new Date(data_programare),
          created_at: new Date(),
          updated_at: new Date()
        }
      });

      await logMedicalActivity(payload.email, 'create_appointment', {
        success: true,
        appointment_id: appointment.id,
        patient_id,
        patient_email: patient.email,
        serviciu,
        data_programare,
        notes
      }, ipAddress, userAgent);

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
      
      await logMedicalActivity(payload.email, 'create_appointment', {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      }, ipAddress, userAgent);
      
      set.status = 500;
      return { error: "Eroare la crearea programării" };
    }
  }, {
    body: t.Object({
      patient_id: t.String(),
      serviciu: t.String(),
      data_programare: t.String(),
      notes: t.Optional(t.String())
    })
  })

  // Vizualizare programări
  .get("/appointments", async ({ request, payload }) => {
    try {
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";

      const appointments = await prisma.programari.findMany({
        include: {
          users: {
            select: {
              id: true,
              email: true,
              username: true
            }
          }
        },
        orderBy: { data_programare: 'asc' }
      });

      await logMedicalActivity(payload.email, 'view_appointments', {
        appointments_count: appointments.length
      }, ipAddress, userAgent);

      return { appointments };
    } catch (error) {
      console.error("Error fetching appointments:", error);
      return { error: "Eroare la încărcarea programărilor" };
    }
  })

  // Actualizare programare
  .put("/appointments/:id", async ({ params, body, set, request, payload }) => {
    try {
      const { id } = params;
      const { serviciu, data_programare, notes } = body as any;
      
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";

      const existingAppointment = await prisma.programari.findUnique({
        where: { id: parseInt(id) },
        include: { users: true }
      });

      if (!existingAppointment) {
        await logMedicalActivity(payload.email, 'update_appointment', {
          success: false,
          reason: 'Appointment not found',
          appointment_id: id
        }, ipAddress, userAgent);
        
        set.status = 404;
        return { error: "Programarea nu a fost găsită" };
      }

      const updatedAppointment = await prisma.programari.update({
        where: { id: parseInt(id) },
        data: {
          serviciu,
          data_programare: new Date(data_programare),
          updated_at: new Date()
        }
      });

      await logMedicalActivity(payload.email, 'update_appointment', {
        success: true,
        appointment_id: id,
        patient_id: existingAppointment.user_id,
        patient_email: existingAppointment.users.email,
        old_data: {
          serviciu: existingAppointment.serviciu,
          data_programare: existingAppointment.data_programare
        },
        new_data: { serviciu, data_programare, notes }
      }, ipAddress, userAgent);

      return { 
        message: "Programare actualizată cu succes",
        appointment: updatedAppointment 
      };
    } catch (error) {
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";
      
      await logMedicalActivity(payload.email, 'update_appointment', {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      }, ipAddress, userAgent);
      
      set.status = 500;
      return { error: "Eroare la actualizarea programării" };
    }
  })

  // Ștergere programare
  .delete("/appointments/:id", async ({ params, set, request, payload }) => {
    try {
      const { id } = params;
      
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";

      const existingAppointment = await prisma.programari.findUnique({
        where: { id: parseInt(id) },
        include: { users: true }
      });

      if (!existingAppointment) {
        await logMedicalActivity(payload.email, 'delete_appointment', {
          success: false,
          reason: 'Appointment not found',
          appointment_id: id
        }, ipAddress, userAgent);
        
        set.status = 404;
        return { error: "Programarea nu a fost găsită" };
      }

      await prisma.programari.delete({
        where: { id: parseInt(id) }
      });

      await logMedicalActivity(payload.email, 'delete_appointment', {
        success: true,
        appointment_id: id,
        patient_id: existingAppointment.user_id,
        patient_email: existingAppointment.users.email,
        deleted_data: {
          serviciu: existingAppointment.serviciu,
          data_programare: existingAppointment.data_programare
        }
      }, ipAddress, userAgent);

      return { message: "Programare ștearsă cu succes" };
    } catch (error) {
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";
      
      await logMedicalActivity(payload.email, 'delete_appointment', {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      }, ipAddress, userAgent);
      
      set.status = 500;
      return { error: "Eroare la ștergerea programării" };
    }
  })

  // Vizualizare pacienți
  .get("/patients", async ({ request, payload }) => {
    try {
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";

      const patients = await prisma.users.findMany({
        where: { role: 'pacient' },
        select: {
          id: true,
          email: true,
          username: true,
          created_at: true,
          programari: {
            select: {
              id: true,
              serviciu: true,
              data_programare: true
            }
          }
        }
      });

      await logMedicalActivity(payload.email, 'view_patients', {
        patients_count: patients.length
      }, ipAddress, userAgent);

      return { patients };
    } catch (error) {
      console.error("Error fetching patients:", error);
      return { error: "Eroare la încărcarea pacienților" };
    }
  });
