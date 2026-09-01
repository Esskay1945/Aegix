import * as THREE from 'three';
import { EffectComposer } from 'three/examples/jsm/postprocessing/EffectComposer.js';
import { RenderPass } from 'three/examples/jsm/postprocessing/RenderPass.js';
import { UnrealBloomPass } from 'three/examples/jsm/postprocessing/UnrealBloomPass.js';

export class ParticlesSwarm {
    constructor(container, count = 50000) {
        this.count = count;
        this.container = container;
        this.speedMult = 0.8;
        
        // SETUP
        this.scene = new THREE.Scene();
        this.scene.fog = new THREE.FogExp2(0x000000, 0.01);
        this.camera = new THREE.PerspectiveCamera(60, window.innerWidth / window.innerHeight, 0.1, 2000);
        this.camera.position.set(0, 0, 100);
        
        this.renderer = new THREE.WebGLRenderer({ antialias: true, powerPreference: "high-performance" });
        this.renderer.setSize(window.innerWidth, window.innerHeight);
        this.container.appendChild(this.renderer.domElement);

        // POST PROCESSING
        this.composer = new EffectComposer(this.renderer);
        this.composer.addPass(new RenderPass(this.scene, this.camera));
        const bloomPass = new UnrealBloomPass(new THREE.Vector2(window.innerWidth, window.innerHeight), 1.5, 0.4, 0.85);
        bloomPass.strength = 1.8; bloomPass.radius = 0.4; bloomPass.threshold = 0;
        this.composer.addPass(bloomPass);

        // OBJECTS
        this.dummy = new THREE.Object3D();
        this.color = new THREE.Color();
        this.target = new THREE.Vector3();
        this.pColor = new THREE.Color();
        
        this.geometry = new THREE.TetrahedronGeometry(0.25);
        this.material = new THREE.MeshBasicMaterial({ color: 0xffffff });
        
        this.mesh = new THREE.InstancedMesh(this.geometry, this.material, this.count);
        this.mesh.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
        this.scene.add(this.mesh);
        
        this.positions = [];
        for(let i=0; i<this.count; i++) {
            this.positions.push(new THREE.Vector3((Math.random()-0.5)*100, (Math.random()-0.5)*100, (Math.random()-0.5)*100));
            this.mesh.setColorAt(i, this.color.setHex(0x00ff88));
        }
        
        this.clock = new THREE.Clock();
        this.animate = this.animate.bind(this);
        this.animate();
    }

    animate() {
        requestAnimationFrame(this.animate);
        const time = this.clock.getElapsedTime() * this.speedMult;
        
        if(this.material.uniforms && this.material.uniforms.uTime) {
            this.material.uniforms.uTime.value = time;
        }

        // API Stubs
        const PARAMS = {"nebulaSize":30,"petalCurl":1.15,"rotationRate":0.32,"cloudDepth":3.4,"corePulse":0.75,"turbulence":0.7};
        const addControl = (id, l, min, max, val) => {
             return PARAMS[id] !== undefined ? PARAMS[id] : val;
        };
        const setInfo = () => {};
        const annotate = () => {};
        let THREE_LIB = THREE;
        
        let THREE_LIB = THREE;
        const count = this.count; // Alias for user code
        
        for(let i=0; i<this.count; i++) {
            let target = this.target;
            let color = this.pColor;
            
            // INJECTED CODE
            const nebulaSize = addControl(
            "nebulaSize",
            "Rose Bloom Radius",
            12.0,
            48.0,
            30.0
            );
            
            const petalCurl = addControl(
            "petalCurl",
            "Petal Curl",
            0.2,
            2.4,
            1.15
            );
            
            const rotationRate = addControl(
            "rotationRate",
            "Nebular Rotation",
            0.0,
            1.5,
            0.32
            );
            
            const cloudDepth = addControl(
            "cloudDepth",
            "Cloud Depth",
            0.5,
            8.0,
            3.4
            );
            
            const corePulse = addControl(
            "corePulse",
            "Core Pulse",
            0.0,
            2.5,
            0.75
            );
            
            const turbulence = addControl(
            "turbulence",
            "Gas Turbulence",
            0.0,
            2.0,
            0.7
            );
            
            const safeCount = Math.max(1.0, count);
            const unitIndex = i / safeCount;
            
            const tau = Math.PI * 2.0;
            const goldenAngle = 2.399963229728653;
            const phaseTime = time * rotationRate;
            
            /*
            Deterministic pseudo-random values.
            
            These remain stable between frames, preventing the nebula
            from flickering like particles generated with Math.random().
            */
            const hashA = Math.sin((i + 1.0) * 12.9898) * 43758.5453;
            const hashB = Math.sin((i + 1.0) * 78.233) * 24634.6345;
            const hashC = Math.sin((i + 1.0) * 39.425) * 15731.7431;
            
            const randA = hashA - Math.floor(hashA);
            const randB = hashB - Math.floor(hashB);
            const randC = hashC - Math.floor(hashC);
            
            const signedA = randA * 2.0 - 1.0;
            const signedB = randB * 2.0 - 1.0;
            const signedC = randC * 2.0 - 1.0;
            
            let px = 0.0;
            let py = 0.0;
            let pz = 0.0;
            
            let hue = 0.93;
            let saturation = 0.9;
            let lightness = 0.5;
            
            /*
            70% OF PARTICLES:
            Layered rose-shaped ionized-gas petals.
            */
            if (unitIndex < 0.70) {
            const local = unitIndex / 0.70;
            
            const layerPosition = local * 7.0;
            const layer = Math.min(6.0, Math.floor(layerPosition));
            const layerFraction = layerPosition - layer;
            
            /*
            Inner layers contain fewer petals.
            Outer layers contain more petals and greater spread.
            */
            const petalCount = 7.0 + layer;
            
            const petalPosition = layerFraction * petalCount;
            const petal = Math.floor(petalPosition);
            const along = petalPosition - petal;
            
            const petalArc = Math.sin(Math.PI * along);
            const layerScale = layer / 6.0;
            
            const breathing =
            1.0 +
            0.035 *
            Math.sin(
            time * corePulse +
            layer * 0.9
            );
            
            const baseAngle =
            (petal / petalCount) * tau +
            layer * goldenAngle * 0.34;
            
            const curlAngle =
            baseAngle +
            phaseTime * (0.34 - layerScale * 0.18) +
            petalCurl *
            (along - 0.18) *
            (0.75 + layerScale * 0.85) +
            signedC * 0.045 * turbulence;
            
            const radialStart =
            nebulaSize *
            (0.08 + layerScale * 0.43);
            
            const radialGrowth =
            nebulaSize *
            (0.20 + layerScale * 0.22) *
            along;
            
            const radialRipple =
            nebulaSize *
            0.018 *
            turbulence *
            Math.sin(
            along * 13.0 +
            layer * 2.1 +
            time * 0.42
            );
            
            const radius =
            (radialStart + radialGrowth + radialRipple) *
            breathing;
            
            /*
            Particle displacement across each petal produces
            broad, cloudy structures instead of thin lines.
            */
            const petalWidth =
            nebulaSize *
            (0.025 + layerScale * 0.055) *
            petalArc *
            (0.35 + 0.65 * randB);
            
            const sideOffset = signedA * petalWidth;
            
            const ca = Math.cos(curlAngle);
            const sa = Math.sin(curlAngle);
            
            const tangentAngle =
            curlAngle + Math.PI * 0.5;
            
            const ct = Math.cos(tangentAngle);
            const st = Math.sin(tangentAngle);
            
            px =
            ca * radius +
            ct * sideOffset;
            
            pz =
            sa * radius +
            st * sideOffset;
            
            py =
            signedB *
            cloudDepth *
            petalArc *
            (0.35 + layerScale * 0.95) +
            Math.sin(
            curlAngle * 3.0 -
            time * 0.28 +
            layer
            ) *
            cloudDepth *
            0.12 *
            turbulence;
            
            /*
            Alternating brightness creates dark dusty channels
            between the luminous emission regions.
            */
            const dustLane =
            0.5 +
            0.5 *
            Math.sin(
            petal * 2.7 +
            along * 18.0 +
            layer * 1.3
            );
            
            const edgeGlow =
            Math.pow(petalArc, 0.45);
            
            hue =
            0.955 -
            layerScale * 0.085 +
            signedC * 0.018;
            
            saturation =
            0.72 +
            edgeGlow * 0.26;
            
            lightness =
            0.14 +
            edgeGlow * 0.48 +
            (1.0 - layerScale) * 0.10 -
            dustLane * 0.10;
            }
            
            /*
            14% OF PARTICLES:
            Dense central cluster and hot glowing nebular core.
            */
            else if (unitIndex < 0.84) {
            const local =
            (unitIndex - 0.70) / 0.14;
            
            const coreRadius =
            nebulaSize *
            0.16 *
            Math.pow(local, 0.36);
            
            const coreTheta =
            i * goldenAngle +
            phaseTime * 0.8;
            
            const coreY =
            1.0 - 2.0 * randB;
            
            const coreRing =
            Math.sqrt(
            Math.max(
            0.0,
            1.0 - coreY * coreY
            )
            );
            
            const pulse =
            1.0 +
            0.13 *
            Math.sin(
            time * corePulse * 2.0 +
            i * 0.013
            );
            
            px =
            Math.cos(coreTheta) *
            coreRing *
            coreRadius *
            pulse;
            
            py =
            coreY *
            coreRadius *
            pulse;
            
            pz =
            Math.sin(coreTheta) *
            coreRing *
            coreRadius *
            pulse;
            
            hue =
            0.07 +
            randC * 0.05;
            
            saturation =
            0.52 +
            randA * 0.28;
            
            lightness =
            0.56 +
            (1.0 - local) * 0.38;
            }
            
            /*
            12% OF PARTICLES:
            Diffuse violet and magenta outer nebular halo.
            */
            else if (unitIndex < 0.96) {
            const local =
            (unitIndex - 0.84) / 0.12;
            
            const haloAngle =
            i * goldenAngle +
            phaseTime * 0.12;
            
            const haloRadius =
            nebulaSize *
            (
            0.72 +
            local * 0.66 +
            signedA * 0.08
            );
            
            const haloWarp =
            1.0 +
            0.10 *
            Math.sin(
            haloAngle * 5.0 +
            time * 0.25
            ) +
            0.05 *
            turbulence *
            Math.sin(
            haloAngle * 11.0 -
            time * 0.17
            );
            
            px =
            Math.cos(haloAngle) *
            haloRadius *
            haloWarp;
            
            pz =
            Math.sin(haloAngle) *
            haloRadius *
            haloWarp;
            
            py =
            signedB *
            cloudDepth *
            (1.2 + local * 1.8) +
            Math.sin(
            haloAngle * 2.0 +
            time * 0.2
            ) *
            cloudDepth *
            0.35;
            
            hue =
            0.79 +
            randC * 0.13;
            
            saturation =
            0.58 +
            randA * 0.30;
            
            lightness =
            0.12 +
            (1.0 - local) * 0.22 +
            randB * 0.12;
            }
            
            /*
            4% OF PARTICLES:
            Sparse background stars surrounding the nebula.
            */
            else {
            const local =
            (unitIndex - 0.96) / 0.04;
            
            const starAngle =
            i * goldenAngle;
            
            const starY =
            signedB;
            
            const starRing =
            Math.sqrt(
            Math.max(
            0.0,
            1.0 - starY * starY
            )
            );
            
            const starRadius =
            nebulaSize *
            (
            1.25 +
            local * 1.10 +
            randA * 0.55
            );
            
            const twinkle =
            0.5 +
            0.5 *
            Math.sin(
            time *
            (1.2 + randC * 2.2) +
            i * 0.17
            );
            
            px =
            Math.cos(starAngle) *
            starRing *
            starRadius;
            
            py =
            starY *
            starRadius *
            0.72;
            
            pz =
            Math.sin(starAngle) *
            starRing *
            starRadius;
            
            hue =
            0.55 +
            randC * 0.12;
            
            saturation =
            0.18 +
            randA * 0.35;
            
            lightness =
            0.32 +
            twinkle * 0.50;
            }
            
            /*
            Final stability and colour-range protection.
            */
            lightness = Math.max(
            0.02,
            Math.min(0.98, lightness)
            );
            
            saturation = Math.max(
            0.0,
            Math.min(1.0, saturation)
            );
            
            hue = hue - Math.floor(hue);
            
            target.set(px, py, pz);
            color.setHSL(
            hue,
            saturation,
            lightness
            );
            
            if (i === 0) {
            setInfo(
            "The Cosmic Rose Nebula",
            "A blooming stellar nursery formed from luminous gas petals, dark dusty lanes, a pulsing young star cluster, and a faint expanding halo."
            );
            
            annotate(
            "rose_core",
            new THREE.Vector3(0, 0, 0),
            "Young Star Cluster"
            );
            
            annotate(
            "rose_petals",
            new THREE.Vector3(
            nebulaSize * 0.58,
            cloudDepth * 0.4,
            0
            ),
            "Ionized Gas Petals"
            );
            
            annotate(
            "rose_halo",
            new THREE.Vector3(
            -nebulaSize * 1.05,
            -cloudDepth * 0.3,
            0
            ),
            "Outer Nebular Halo"
            );
            }
            
            // UPDATE
            this.positions[i].lerp(this.target, 0.1);
            this.dummy.position.copy(this.positions[i]);
            this.dummy.updateMatrix();
            this.mesh.setMatrixAt(i, this.dummy.matrix);
            this.mesh.setColorAt(i, this.pColor);
        }
        this.mesh.instanceMatrix.needsUpdate = true;
        this.mesh.instanceColor.needsUpdate = true;
        
        this.composer.render();
    }
    
    dispose() {
        this.geometry.dispose();
        this.material.dispose();
        this.scene.remove(this.mesh);
        this.renderer.dispose();
    }
}