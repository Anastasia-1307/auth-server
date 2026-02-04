import { Elysia, t } from "elysia";
import { verifyToken, JWTPayload } from "../lib/jwt-service";
import { prisma } from "../lib/prisma";
import { logResourceAccess } from "../services/user-activity-service";

export const dashboardRoutes = new Elysia({ prefix: "/dashboard" })
  
  // Middleware pentru verificare token
  .derive(async ({ request, set }) => {
    const auth = request.headers.get("authorization");
    
    if (!auth || !auth.startsWith("Bearer ")) {
      set.status = 401;
      throw new Error("Unauthorized");
    }

    const token = auth.slice(7);
    const payload: JWTPayload = await verifyToken(token, "nextjs_client");
    
    return { payload };
  })

  // Obține specialități cu număr de medici
  .get("/specialitati", async ({ request, payload }) => {
    try {
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";

      const specialitati = await prisma.specialitati.findMany({
        include: {
          _count: {
            select: {
              medici: true
            }
          }
        },
        orderBy: {
          nume: 'asc'
        }
      });

      await logResourceAccess(payload.email, 'specialitati', 'view', ipAddress, userAgent, {
        count: specialitati.length
      });

      return specialitati;
    } catch (error) {
      console.error("Error fetching specialitati:", error);
      return { error: "Eroare la încărcarea specialităților" };
    }
  })

  // Obține medici cu informații complete
  .get("/medici", async ({ request, payload }) => {
    try {
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";

      const medici = await prisma.users.findMany({
        where: { role: 'medic' },
        include: {
          medic_info: {
            include: {
              specialitate: true,
              program_lucru: true
            }
          }
        },
        orderBy: {
          username: 'asc'
        }
      });

      await logResourceAccess(payload.email, 'medici', 'view', ipAddress, userAgent, {
        count: medici.length
      });

      // Transformăm datele pentru formatul așteptat
      const formattedMedici = medici.map(medic => ({
        id: medic.id,
        user_id: medic.id,
        specialitate_id: medic.medic_info?.specialitate_id || 0,
        titlu: medic.medic_info?.titlu,
        experienta_ani: medic.medic_info?.experienta_ani,
        telefon: medic.medic_info?.telefon,
        cabinet: medic.medic_info?.cabinet,
        pret_consultatie: medic.medic_info?.pret_consultatie,
        bio: medic.medic_info?.bio,
        rating: medic.medic_info?.rating,
        user: {
          id: medic.id,
          username: medic.username,
          email: medic.email
        },
        specialitate: medic.medic_info?.specialitate || { id: 0, nume: "Nespecificat" },
        program_lucru: medic.medic_info?.program_lucru || []
      }));

      return formattedMedici;
    } catch (error) {
      console.error("Error fetching medici:", error);
      return { error: "Eroare la încărcarea medicilor" };
    }
  })

  // Obține disponibilitatea unui medic pentru o anumită dată
  .get("/medici/:medicId/disponibilitate", async ({ params, query, request, payload }) => {
    try {
      const { medicId } = params;
      const { data } = query as any;
      
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";

      if (!data) {
        return { error: "Data este obligatorie" };
      }

      // Obținem ziua săptămânii (0 = Duminică, 1 = Luni, ..., 6 = Sâmbătă)
      const dataObj = new Date(data);
      const ziSaptamana = dataObj.getDay() === 0 ? 7 : dataObj.getDay();

      // Obținem programul de lucru al medicului pentru acea zi
      const medic = await prisma.users.findUnique({
        where: { 
          id: medicId,
          role: 'medic'
        },
        include: {
          medic_info: {
            include: {
              program_lucru: {
                where: { zi_saptamana }
              }
            }
          }
        }
      });

      if (!medic) {
        return { error: "Medicul nu a fost găsit" };
      }

      // Obținem programările existente pentru acea dată
      const programariExistente = await prisma.programari.findMany({
        where: {
          medic_id: medicId,
          data_programare: {
            gte: new Date(data + "T00:00:00.000Z"),
            lt: new Date(data + "T23:59:59.999Z")
          }
        },
        select: {
          data_programare: true,
          status: true
        }
      });

      // Generăm ore disponibile
      const programLucru = medic.medic_info?.program_lucru[0];
      const oreDisponibile = [];

      if (programLucru) {
        const [oraInceput, minutInceput] = programLucru.ora_inceput.split(':').map(Number);
        const [oraSfarsit, minutSfarsit] = programLucru.ora_sfarsit.split(':').map(Number);

        let oraCurenta = oraInceput;
        let minutCurent = minutInceput;

        while (oraCurenta < oraSfarsit || (oraCurenta === oraSfarsit && minutCurent < minutSfarsit)) {
          const oraFormatata = `${oraCurenta.toString().padStart(2, '0')}:${minutCurent.toString().padStart(2, '0')}`;
          const dataOra = new Date(`${data}T${oraFormatata}:00.000Z`);
          
          // Verificăm dacă ora este disponibilă
          const esteOcupata = programariExistente.some(prog => 
            new Date(prog.data_programare).getTime() === dataOra.getTime()
          );

          if (!esteOcupata) {
            oreDisponibile.push({
              ora: oraFormatata,
              disponibila: true
            });
          }

          // Adăugăm 30 de minute
          minutCurent += 30;
          if (minutCurent >= 60) {
            minutCurent = 0;
            oraCurenta += 1;
          }
        }
      }

      await logResourceAccess(payload.email, 'disponibilitate_medic', 'view', ipAddress, userAgent, {
        medic_id: medicId,
        data,
        ore_disponibile: oreDisponibile.length
      });

      return {
        medic: {
          id: medic.id,
          username: medic.username,
          specialitate: medic.medic_info?.specialitate
        },
        data,
        program_lucru: programLucru,
        ore_disponibile: oreDisponibile,
        programari_existente: programariExistente.length
      };
    } catch (error) {
      console.error("Error fetching disponibilitate:", error);
      return { error: "Eroare la încărcarea disponibilității" };
    }
  });
