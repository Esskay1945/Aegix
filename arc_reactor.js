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
        const PARAMS = {"scale":55,"rotation":0.8,"chaos":0.7};
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
            const scale = addControl("scale", "Reactor Size", 20, 100, 55);
            const rotation = addControl("rotation", "Rotation Speed", 0, 3, 0.8);
            const chaos = addControl("chaos", "Energy Chaos", 0, 2, 0.7);
            
            const u = i / count;
            const golden = 2.3999632297;
            const theta = i * golden;
            const y = 1 - 2 * u;
            const r = Math.sqrt(Math.max(0, 1 - y * y));
            const x = r * Math.cos(theta);
            const z = r * Math.sin(theta);
            
            const t = time * rotation;
            
            const ring = Math.floor(i % 7);
            const ringAngle = theta + t * (ring % 2 === 0 ? 1 : -1);
            const ringRadius = scale * (0.45 + ring * 0.075);
            
            const wave = Math.sin(theta * 9 + time * 3 + y * 12) * chaos;
            const outer = scale * (1 + wave * 0.045);
            
            let px = x * outer;
            let py = y * outer;
            let pz = z * outer;
            
            const core = Math.exp(-u * 18);
            px *= 1 - core * 0.35;
            py *= 1 - core * 0.35;
            pz *= 1 - core * 0.35;
            
            const ca = Math.cos(t * 0.7);
            const sa = Math.sin(t * 0.7);
            
            const rx = px * ca - pz * sa;
            const rz = px * sa + pz * ca;
            
            target.set(rx, py, rz);
            
            const pulse = 0.5 + 0.5 * Math.sin(time * 4 + theta * 3);
            const hue = 0.07 + pulse * 0.025;
            const light = 0.38 + pulse * 0.22;
            
            color.setHSL(hue, 1.0, light);
            
            if (i === 0) {
                setInfo("ARC REACTOR", "Holographic particle energy core");
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